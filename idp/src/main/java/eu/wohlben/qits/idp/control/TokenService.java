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
 * ({@link ClientRoles}). A user credential gets none — {@link #workstation} and {@link #cli} are
 * the other two mints here, and neither stamps a client identity onto a person.
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

  /** A CLI access token is as short-lived as a workstation's, and configured on its own key. */
  @ConfigProperty(name = "qits.idp.cli.access-token-ttl-seconds")
  long cliAccessTokenTtlSeconds;

  /**
   * The resources a signed-in CLI may target — CONFIGURED, never derived from the request.
   *
   * <p>By default it is one platform-wide audience, {@code qits-platform}, with no environment
   * prefix: the edge and every service accept it, and the token's roles decide what the person may
   * do. A CLI naming its own audience would be a public client choosing its own blast radius, so
   * {@code /authorize} refuses an {@code audience} parameter for this client outright and this value
   * is the whole answer.
   */
  @ConfigProperty(name = "qits.idp.cli.audiences")
  List<String> cliAudiences;

  @Inject SigningKeys signingKeys;

  @Inject ClientRegistry clients;

  @Inject Users users;

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
   * Mint the credential a person's command-line tool holds after signing in through the browser.
   *
   * <p><b>It carries the person's own roles</b>, and that is the decision the epic records rather
   * than an oversight: a CLI that could do less than the browser the same person just signed in
   * with would be a tool that cannot do the job it exists for.  The token is therefore as strong as
   * that session, and the defences are elsewhere — fifteen minutes of access-token life, refresh
   * rotation with replay detection revoking the whole family, and a revoke button per device.
   * Tokens narrowed to a project or a service are named later work.
   *
   * <p><b>It carries no {@code clients/…} self-role</b>, for the same reason {@link #workstation}
   * does not: that stamp means "this bearer IS that machine client", and a person is not one.  A
   * role a user somehow holds under that prefix is dropped here rather than trusted, so the machine
   * identity a resource service gates on stays unreachable through a login however the user store
   * was written to.
   *
   * <p>The audiences are {@code qits.idp.cli.audiences}, which the public client cannot influence.
   */
  public IssuedToken cli(UUID userId) {
    Users.Account account =
        users
            .byId(userId)
            .orElseThrow(
                () ->
                    OAuthException.invalidGrant(
                        "the account this credential was approved for no longer exists"));
    if (cliAudiences.isEmpty()) {
      LOG.warn("a cli token was refused: qits.idp.cli.audiences is empty");
      throw OAuthException.invalidTarget("this installation configures no cli audience");
    }
    Set<String> groups = new LinkedHashSet<>();
    for (String role : account.roles()) {
      if (!role.startsWith(ClientRoles.SELF_PREFIX)) {
        groups.add(role);
      }
    }
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();
    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(userId.toString())
            .audience(new LinkedHashSet<>(cliAudiences))
            .groups(groups)
            .claim("credential_type", "cli")
            .issuedAt(now)
            .expiresAt(now.plusSeconds(cliAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, cliAccessTokenTtlSeconds, List.copyOf(cliAudiences));
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
