package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The issuer URL, in one place.
 *
 * <p>The {@code iss} of every token and the base of every advertised endpoint are the same string,
 * and a consumer rejects a token whose {@code iss} differs from the discovery document's {@code
 * issuer} by one character. Normalising once — here — is what keeps a configured trailing slash
 * from becoming that character.
 */
@ApplicationScoped
public class Issuer {

  @ConfigProperty(name = "qits.idp.issuer")
  String configured;

  /** The issuer string: {@code qits.idp.issuer} trimmed, with any trailing slash removed. */
  public String url() {
    String url = configured.trim();
    while (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }
    return url;
  }

  /** {@code <issuer>/token} — derived, never separately configured. */
  public String tokenEndpoint() {
    return url() + "/token";
  }

  /** {@code <issuer>/authorize} — the Git workstation's Authorization Code + PKCE browser leg. */
  public String authorizationEndpoint() {
    return url() + "/authorize";
  }

  /** {@code <issuer>/jwks} — derived, never separately configured. */
  public String jwksUri() {
    return url() + "/jwks";
  }
}
