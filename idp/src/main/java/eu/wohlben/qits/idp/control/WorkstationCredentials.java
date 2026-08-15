package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpAuthorizationCode;
import eu.wohlben.qits.idp.entity.IdpWorkstationRefreshToken;
import eu.wohlben.qits.idp.error.OAuthException;
import eu.wohlben.qits.idp.persistence.IdpAuthorizationCodeRepository;
import eu.wohlben.qits.idp.persistence.IdpWorkstationRefreshTokenRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Authorization codes and rotating refresh credentials for the Git workstation public client.
 *
 * <p>This is deliberately separate from {@link ClientRegistry}: a workstation is a user-approved
 * public client, not a service identity.  It can mint only the externally constrained Git token and
 * never receives a client secret or either system role.
 */
@ApplicationScoped
public class WorkstationCredentials {

  @ConfigProperty(name = "qits.idp.workstation.authorization-code-ttl")
  Duration authorizationCodeTtl;

  @ConfigProperty(name = "qits.idp.workstation.refresh-token-ttl")
  Duration refreshTokenTtl;

  @Inject IdpAuthorizationCodeRepository codes;

  @Inject IdpWorkstationRefreshTokenRepository refreshTokens;

  public record AuthorizationCode(String value) {}

  public record Grant(UUID userId) {}

  /** A family is the revocation unit and intentionally exposes no credential material. */
  public record Workstation(UUID id, Instant createdAt, Instant expiresAt, Instant revokedAt) {}

  /** Create a code after the HTTP boundary has validated every protocol parameter. */
  public AuthorizationCode authorize(UUID userId, String redirectUri, String codeChallenge) {
    return DbRetry.inNewTx(
        "create a workstation authorization code",
        () -> {
          String value = RandomSecret.credential();
          Instant now = now();
          IdpAuthorizationCode row = new IdpAuthorizationCode();
          row.id = UUID.randomUUID();
          row.codeHash = ClientSecret.hash(value);
          row.userId = userId;
          row.redirectUri = redirectUri;
          row.codeChallenge = codeChallenge;
          row.createdAt = now;
          row.expiresAt = now.plus(authorizationCodeTtl);
          codes.persist(row);
          return new AuthorizationCode(value);
        });
  }

  /**
   * Spend a code exactly once and start a refresh-token family in the same transaction.
   *
   * <p>A duplicate code exchange is a normal {@code invalid_grant}; it has no refresh family to
   * revoke because the first exchange's family remains valid for the workstation that won.
   */
  public RefreshGrant exchangeCode(String code, String redirectUri, String verifier) {
    requireVerifier(verifier);
    return DbRetry.inNewTx(
        "exchange a workstation authorization code",
        () -> {
          IdpAuthorizationCode row = codes.lockByCodeHash(ClientSecret.hash(required(code, "code")));
          Instant now = now();
          if (row == null
              || row.consumedAt != null
              || !row.expiresAt.isAfter(now)
              || !row.redirectUri.equals(redirectUri)
              || !constantTimeEquals(row.codeChallenge, s256(verifier))) {
            throw OAuthException.invalidGrant("authorization code is invalid, expired, or already used");
          }
          row.consumedAt = now;
          return newRefresh(row.userId, UUID.randomUUID(), now);
        });
  }

  /** Rotate a refresh token. Replaying any used, expired or revoked value revokes its whole family. */
  public RefreshGrant refresh(String token) {
    RefreshAttempt attempt =
        DbRetry.inNewTx(
        "rotate a workstation refresh token",
        () -> {
          IdpWorkstationRefreshToken row =
              refreshTokens.lockByTokenHash(ClientSecret.hash(required(token, "refresh_token")));
          Instant now = now();
          if (row == null) {
            throw OAuthException.invalidGrant("refresh token is invalid");
          }
          if (row.usedAt != null || row.revokedAt != null || !row.expiresAt.isAfter(now)) {
            // This includes an honest race between two refreshes.  That is intentionally fail closed:
            // a client must re-authorize rather than leave a stolen rotating credential alive.
            // Do not throw inside this transaction: throwing rolls the revocation back. The small
            // result lets the transaction close normally; the family is then revoked in its own
            // committed boundary below before the protocol refusal leaves this method.
            return RefreshAttempt.replay(row.familyId);
          }
          row.usedAt = now;
          return RefreshAttempt.granted(newRefresh(row.userId, row.familyId, now));
        });
    if (attempt.replayFamily() != null) {
      DbRetry.runInNewTx(
          "revoke a replayed workstation refresh-token family",
          () -> refreshTokens.revokeFamily(attempt.replayFamily(), now()));
      throw OAuthException.invalidGrant("refresh token is invalid or has been replayed");
    }
    return attempt.grant();
  }

  /** The signed-in user sees one entry per family, not every historical rotation link. */
  public List<Workstation> list(UUID userId) {
    return DbRetry.inNewTx(
        "list workstation credentials",
        () -> {
          Map<UUID, IdpWorkstationRefreshToken> newest = new LinkedHashMap<>();
          for (IdpWorkstationRefreshToken row : refreshTokens.listFamiliesForUser(userId)) {
            newest.merge(
                row.familyId,
                row,
                (left, right) -> left.createdAt.isAfter(right.createdAt) ? left : right);
          }
          return newest.values().stream()
              .map(row -> new Workstation(row.familyId, row.createdAt, row.expiresAt, row.revokedAt))
              .sorted(Comparator.comparing(Workstation::createdAt).reversed())
              .toList();
        });
  }

  /** Revoke only a family owned by the signed-in user; foreign ids are indistinguishable from absent. */
  public boolean revoke(UUID userId, UUID familyId) {
    return DbRetry.inNewTx(
        "revoke a workstation credential",
        () -> {
          List<IdpWorkstationRefreshToken> rows =
              refreshTokens.find("familyId = ?1 and userId = ?2", familyId, userId).list();
          if (rows.isEmpty()) {
            return false;
          }
          refreshTokens.revokeFamily(familyId, now());
          return true;
        });
  }

  public record RefreshGrant(UUID userId, String refreshToken) {}

  private record RefreshAttempt(RefreshGrant grant, UUID replayFamily) {
    static RefreshAttempt granted(RefreshGrant grant) {
      return new RefreshAttempt(grant, null);
    }

    static RefreshAttempt replay(UUID familyId) {
      return new RefreshAttempt(null, familyId);
    }
  }

  private RefreshGrant newRefresh(UUID userId, UUID familyId, Instant now) {
    String value = RandomSecret.credential();
    IdpWorkstationRefreshToken row = new IdpWorkstationRefreshToken();
    row.id = UUID.randomUUID();
    row.familyId = familyId;
    row.tokenHash = ClientSecret.hash(value);
    row.userId = userId;
    row.createdAt = now;
    row.expiresAt = now.plus(refreshTokenTtl);
    refreshTokens.persist(row);
    return new RefreshGrant(userId, value);
  }

  /** RFC 7636's verifier grammar and length floor keep the S256 encoding unambiguous. */
  public static void requireVerifier(String verifier) {
    if (verifier == null || !verifier.matches("[A-Za-z0-9\\-._~]{43,128}")) {
      throw OAuthException.invalidRequest("code_verifier must be 43 to 128 RFC 7636 characters");
    }
  }

  public static void requireChallenge(String challenge) {
    if (challenge == null || !challenge.matches("[A-Za-z0-9_-]{43,128}")) {
      throw OAuthException.invalidRequest("code_challenge must be a base64url S256 value");
    }
  }

  private static String required(String value, String name) {
    if (value == null || value.isBlank()) {
      throw OAuthException.invalidRequest(name + " is required");
    }
    return value;
  }

  private static String s256(String verifier) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 is required by the JDK", impossible);
    }
  }

  private static boolean constantTimeEquals(String left, String right) {
    return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII), right.getBytes(StandardCharsets.US_ASCII));
  }

  private static Instant now() {
    return Instant.now().truncatedTo(ChronoUnit.MICROS);
  }
}
