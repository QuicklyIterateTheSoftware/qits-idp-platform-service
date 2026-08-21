package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.error.OAuthException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * The {@code client_credentials} grant: authenticate a client, resolve the audiences it may have,
 * and mint an RS256 JWT.
 *
 * <p>The token says who the caller is and what it may be used against. It says nothing about what
 * the caller may do — that decision belongs to the resource service, helped by the shared
 * enforcement library.
 *
 * <p><b>Every client token names its own client.</b> The {@code groups} claim carries the
 * configured roles plus {@code clients/<client-id>}, stamped from the id that just authenticated
 * ({@link ClientRoles}). A user credential gets none — {@link #workstation} is the other mint here
 * and it issues one fixed, deliberately narrow role.
 *
 * <p><b>A commissioned client mints exactly like a service client.</b> This class asks {@link
 * ClientRegistry} for a client and never learns which half answered — that identity is the whole
 * of the commission model working, because it means docker's Bearer dance, quarkus-oidc-client and
 * everything else already wired to this endpoint need no second code path.
 */
@ApplicationScoped
public class TokenService {

  private static final Logger LOG = Logger.getLogger(TokenService.class);

  /** What a caller gets back, before it is dressed as an RFC 6749 token response. */
  public record IssuedToken(String accessToken, long expiresInSeconds, List<String> audiences) {}

  @Inject Issuer issuer;

  @ConfigProperty(name = "qits.idp.token-ttl-seconds")
  long tokenTtlSeconds;

  /** Workstation access tokens deliberately live far less long than service credentials. */
  @ConfigProperty(name = "qits.idp.workstation.access-token-ttl-seconds")
  long workstationAccessTokenTtlSeconds;

  /** The one resource a workstation public client may ever target. */
  @ConfigProperty(name = "qits.idp.workstation.githost-audience")
  String workstationGithostAudience;

  @Inject SigningKeys signingKeys;

  @Inject ClientRegistry clients;

  /**
   * Authenticate and mint.
   *
   * @param requestedAudiences the {@code audience} values the request asked for; empty means "all
   *     of the client's own"
   * @throws OAuthException {@code invalid_client} (401) when authentication fails, {@code
   *     invalid_target} (400) when an audience is not this client's to ask for
   */
  public IssuedToken clientCredentials(
      String clientId, String secret, List<String> requestedAudiences) {
    IdpClient client = clients.authenticate(clientId, secret);

    List<String> audiences = resolveAudiences(client, requestedAudiences);
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();

    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(client.clientId())
            // A Set, so `aud` is always a JSON array — one shape for consumers to read whether the
            // token names one audience or four.
            .audience(new LinkedHashSet<>(audiences))
            // The configured roles AND the client's own `clients/<id>`, which is minted here and
            // grantable nowhere — see ClientRoles.
            .groups(ClientRoles.mintedFor(client))
            .issuedAt(now)
            .expiresAt(now.plusSeconds(tokenTtlSeconds));
    // The granted claims, verbatim. The idp does not interpret these values.
    client.claims().forEach(token::claim);

    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, tokenTtlSeconds, audiences);
  }

  /**
   * Mint the constrained user-approved credential used by a local Git workstation.
   *
   * <p>This does not copy the user's ordinary admin roles. A workstation is intentionally a
   * different capability: the resource sees one external-Git role and a ref pattern claim, and
   * must reject every ref outside that pattern. The audience is fixed in configuration rather than
   * accepted from the public client, so this token can never be replayed at another service.
   *
   * <p><b>And it carries no {@code clients/…} self-role.</b> That stamp says "this bearer IS that
   * machine client"; a token minted to a person's browser approval is not one, so the machine
   * identity a resource service gates on cannot be reached through a login.
   */
  public IssuedToken workstation(UUID userId) {
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();
    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(userId.toString())
            .audience(Set.of(workstationGithostAudience))
            .groups(Set.of("qits:git:external"))
            .claim("credential_type", "workstation")
            .claim("git_ref_pattern", "refs/heads/external/*")
            .issuedAt(now)
            .expiresAt(now.plusSeconds(workstationAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, workstationAccessTokenTtlSeconds, List.of(workstationGithostAudience));
  }

  /**
   * The {@code aud} of the token: what was asked for, or the client's whole allowed list when
   * nothing was asked for.
   */
  private List<String> resolveAudiences(IdpClient client, List<String> requested) {
    List<String> allowed = client.audiences();
    if (allowed.isEmpty()) {
      LOG.warnf("token request refused for client %s: no audiences configured", LoggableClientId.of(client.clientId()));
      throw OAuthException.invalidTarget("this client may request no audience");
    }
    if (requested.isEmpty()) {
      return allowed;
    }
    Set<String> resolved = new LinkedHashSet<>();
    for (String audience : requested) {
      if (!allowed.contains(audience)) {
        LOG.warnf(
            "token request refused for client %s: audience not allowed", LoggableClientId.of(client.clientId()));
        throw OAuthException.invalidTarget("audience is not allowed for this client");
      }
      resolved.add(audience);
    }
    return List.copyOf(resolved);
  }
}
