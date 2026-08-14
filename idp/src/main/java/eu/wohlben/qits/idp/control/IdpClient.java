package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;

/**
 * One client the idp will issue for: its id, its shared secret, the audiences it may ask for, and
 * the structured claims its tokens carry.
 *
 * <p>Two kinds of client arrive here through this one record, and {@link ClientRegistry} is where
 * they meet: the <b>static service clients</b> built from config ({@link IdpClients}), and the
 * <b>commissioned clients</b> built from {@code idp_client} rows ({@link DynamicClients}). Only the
 * secret tells them apart — a configured value against a stored hash — which is the point: a
 * commissioned credential mints exactly like a service client, because {@link TokenService} cannot
 * see which one it has.
 *
 * @param secret how a presented secret is checked; never the raw string, so a stored hash and a
 *     configured value both fit
 * @param audiences the {@code aud} values this client may request; a request naming none gets all
 *     of them
 * @param claims granted claims, copied into the token verbatim
 */
public record IdpClient(
    String clientId, ClientSecret secret, List<String> audiences, Map<String, String> claims) {

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
