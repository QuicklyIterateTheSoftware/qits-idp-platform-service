package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.control.PublicClients.PublicClient;
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
 * Authorization codes and rotating refresh credentials for the public OAuth clients.
 *
 * <p>This is deliberately separate from {@link ClientRegistry}: a workstation or a signed-in CLI is
 * a user-approved public client, not a service identity.  Neither ever receives a client secret or
 * either system role.
 *
 * <p><b>Every code and every refresh link records the client it was approved for</b> ({@code
 * client_id}, from {@link PublicClients}), and every exchange checks it.  Without that column the
 * two public clients would share one credential pool: a code approved for the Git workstation could
 * be spent by {@code qits-cli} and come back as the person's whole set of roles, which is the one
 * way a deliberately narrow credential could become a wide one.  The check is here rather than at
 * the HTTP boundary because it is the row that remembers, not the request.
 */
@ApplicationScoped
public class WorkstationCredentials {

  /**
   * How long a refresh family lives, SHARED BY BOTH PUBLIC CLIENTS.
   *
   * <p>There is no {@code qits.idp.cli.refresh-token-ttl}, and that is a decision rather than an
   * omission: the number answers "how long may a person stay signed in on a device they still
   * hold", which is a property of the person and the installation, not of which tool is asking.
   * Splitting it would invite two values to drift apart and would make "my CLI logged out but my
   * Git did not" a thing an operator has to explain.  Give the CLI its own key on the day the two
   * answers genuinely differ; until then one key is one fact.
   */
  @ConfigProperty(name = "qits.idp.workstation.refresh-token-ttl")
  Duration refreshTokenTtl;

  @Inject IdpAuthorizationCodeRepository codes;

  @Inject IdpWorkstationRefreshTokenRepository refreshTokens;

  public record AuthorizationCode(String value) {}

  public record Grant(UUID userId) {}

  /**
   * A family is the revocation unit and intentionally exposes no credential material.
   *
   * @param clientId which public client this family belongs to — what lets one page list a
   *     person's CLI sessions and Git workstations together and still say which is which
   */
  public record Workstation(
      UUID id, String clientId, Instant createdAt, Instant expiresAt, Instant revokedAt) {}

  /** Create a code after the HTTP boundary has validated every protocol parameter. */
  public AuthorizationCode authorize(
      PublicClient client, UUID userId, String redirectUri, String codeChallenge) {
    return DbRetry.inNewTx(
        "create a public-client authorization code",
        () -> {
          String value = RandomSecret.credential();
          Instant now = now();
          IdpAuthorizationCode row = new IdpAuthorizationCode();
          row.id = UUID.randomUUID();
          row.codeHash = ClientSecret.hash(value);
          row.clientId = client.id();
          row.userId = userId;
          row.redirectUri = redirectUri;
          row.codeChallenge = codeChallenge;
          row.createdAt = now;
          row.expiresAt = now.plus(client.authorizationCodeTtl());
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
  public RefreshGrant exchangeCode(
      PublicClient client, String code, String redirectUri, String verifier) {
    requireVerifier(verifier);
    return DbRetry.inNewTx(
        "exchange a public-client authorization code",
        () -> {
          IdpAuthorizationCode row = codes.lockByCodeHash(ClientSecret.hash(required(code, "code")));
          Instant now = now();
          if (row == null
              || !client.id().equals(row.clientId)
              || row.consumedAt != null
              || !row.expiresAt.isAfter(now)
              || !row.redirectUri.equals(redirectUri)
              || !constantTimeEquals(row.codeChallenge, s256(verifier))) {
            // A code of the other public client is refused in the same breath as an expired one:
            // the caller is told invalid_grant and not which of the six things it was.
            throw OAuthException.invalidGrant("authorization code is invalid, expired, or already used");
          }
          row.consumedAt = now;
          return newRefresh(client.id(), row.userId, UUID.randomUUID(), now);
        });
  }

  /** Rotate a refresh token. Replaying any used, expired or revoked value revokes its whole family. */
  public RefreshGrant refresh(PublicClient client, String token) {
    RefreshAttempt attempt =
        DbRetry.inNewTx(
        "rotate a public-client refresh token",
        () -> {
          IdpWorkstationRefreshToken row =
              refreshTokens.lockByTokenHash(ClientSecret.hash(required(token, "refresh_token")));
          Instant now = now();
          if (row == null || !client.id().equals(row.clientId)) {
            // Presenting one client's refresh token as the other is NOT replay and does not revoke
            // the family: the holder may simply have two grants and crossed them, and punishing a
            // live Git credential for a CLI's mistake would be the wrong trade.  It is refused.
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
          return RefreshAttempt.granted(newRefresh(row.clientId, row.userId, row.familyId, now));
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
              .map(
                  row ->
                      new Workstation(
                          row.familyId, row.clientId, row.createdAt, row.expiresAt, row.revokedAt))
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

  /**
   * A fresh refresh credential and what it was minted for.
   *
   * @param refreshExpiresInSeconds how long the family has left, so the token response can carry
   *     {@code refresh_expires_in} and a client can warn before a session ends rather than
   *     discovering it at the next call.  <b>It is the deadline of the link just issued, and
   *     rotation stamps a fresh one</b> — so this expiry is idle time, not total session age: a
   *     CLI that refreshes weekly never sees it fall, and one left in a drawer does.  That is the
   *     rotation behaviour as it already stood for workstations; the number only makes it visible.
   */
  public record RefreshGrant(UUID userId, String refreshToken, long refreshExpiresInSeconds) {}

  private record RefreshAttempt(RefreshGrant grant, UUID replayFamily) {
    static RefreshAttempt granted(RefreshGrant grant) {
      return new RefreshAttempt(grant, null);
    }

    static RefreshAttempt replay(UUID familyId) {
      return new RefreshAttempt(null, familyId);
    }
  }

  private RefreshGrant newRefresh(String clientId, UUID userId, UUID familyId, Instant now) {
    String value = RandomSecret.credential();
    IdpWorkstationRefreshToken row = new IdpWorkstationRefreshToken();
    row.id = UUID.randomUUID();
    row.familyId = familyId;
    row.clientId = clientId;
    row.tokenHash = ClientSecret.hash(value);
    row.userId = userId;
    row.createdAt = now;
    row.expiresAt = now.plus(refreshTokenTtl);
    refreshTokens.persist(row);
    return new RefreshGrant(userId, value, refreshTokenTtl.toSeconds());
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
