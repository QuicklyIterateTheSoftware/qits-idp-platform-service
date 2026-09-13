package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;

/**
 * One client the idp will issue for: its id, its shared secret, the audiences it may ask for, and
 * the structured claims its tokens carry.
 *
 * <p>Three kinds of client arrive here through this one record, and {@link ClientRegistry} is where
 * they meet: the <b>environment service clients</b> built from config ({@link IdpClients}), the
 * <b>database service clients</b> built from {@code idp_service_client} rows ({@link
 * ServiceClients}), and the <b>commissioned clients</b> built from {@code idp_client} rows ({@link
 * DynamicClients}). Only the secret tells a static one from a commissioned one — a configured value
 * or a stored hash against a stored hash — which is the point: a commissioned credential mints
 * exactly like a service client, because {@link TokenService} cannot see which one it has.
 *
 * @param secret how a presented secret is checked; never the raw string, so a stored hash and a
 *     configured value both fit
 * @param audiences the {@code aud} values this client may request; a request naming none gets all
 *     of them
 * @param claims granted claims, copied into the token verbatim
 * @param contextKind the commission's context kind, stamped as {@code context_kind}; null for a
 *     service client, which carries no such claim
 * @param gitRefs the Git refs this client may push, stamped as {@code git_refs}; null when no list
 *     was stated (every service client), which carries no such claim. Empty means "push nothing".
 * @param audienceSource which transitional audience rule {@link TokenService} applies — see {@link
 *     AudienceSource}
 */
public record IdpClient(
    String clientId,
    ClientSecret secret,
    List<String> audiences,
    List<String> roles,
    Map<String, String> claims,
    String contextKind,
    List<String> gitRefs,
    AudienceSource audienceSource) {

  /**
   * The one extra argument every call site had before {@link #audienceSource} existed: the
   * environment rule, which is what every caller meant.
   */
  public IdpClient(
      String clientId,
      ClientSecret secret,
      List<String> audiences,
      List<String> roles,
      Map<String, String> claims,
      String contextKind,
      List<String> gitRefs) {
    this(clientId, secret, audiences, roles, claims, contextKind, gitRefs, AudienceSource.ENVIRONMENT);
  }

  /**
   * Which transitional audience rule this client's tokens are minted under (C2 of
   * {@code service-client-identity-plan.md}). Both are temporary, for as long as the platform
   * carries clients on both sides of the migration.
   *
   * <ul>
   *   <li>{@link #ENVIRONMENT} — today's rule: a requested audience must be in the client's
   *       configured list or be {@code qits-platform}, and naming none gets the whole list. {@code
   *       qits-platform} is always added on top.
   *   <li>{@link #DATABASE} — a database service client has no configured audience list yet, so a
   *       requested audience is copied back unchecked, beside {@code qits-platform}, which is
   *       always added on top here too.
   * </ul>
   *
   * <p>A commissioned client's tokens follow its owner's rule, because its audiences are the
   * owner's.
   */
  public enum AudienceSource {
    ENVIRONMENT,
    DATABASE
  }

  /**
   * Whether this client can authenticate at all.
   *
   * <p><b>A blank secret is unusable, never open.</b> That is the one decision this record makes:
   * a client seeded without a secret — which is how every service client ships — is refused exactly
   * like a wrong secret, so an unconfigured deployment issues nothing rather than issuing to
   * anyone. It is the opposite reading from {@code qits.artifacts.token}, where a blank value means
   * "no guard"; the difference is that a guard with no secret protects a network already trusted,
   * while an issuer with no secret mints identity for whoever asks.
   */
  public boolean usable() {
    return secret != null && secret.usable();
  }

  /**
   * Whether {@code candidate} is this client's secret. False when the client is unusable, so this
   * is never on its own a reason to issue a token. Constant-time — see {@link ClientSecret}.
   */
  public boolean secretMatches(String candidate) {
    return secret != null && secret.matches(candidate);
  }
}
