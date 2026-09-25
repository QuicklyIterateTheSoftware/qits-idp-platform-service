package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The issuer string and the advertised endpoint base, in one place — and they are TWO values, not
 * one.
 *
 * <p>They were one string for as long as the idp answered on one name. The {@code iss} of every
 * token was also the address a consumer dialled, so deriving {@code <issuer>/jwks} from it could
 * not be wrong. Deleting the platform plane ended that: the idp's bare alias {@code
 * qits-platform-idp} stopped resolving and its address became {@code <env>-qits-platform-idp},
 * while the issuer deliberately did NOT move — a string compared for equality cannot be covered by
 * a second DNS alias and cannot hold two values, so moving it would have rejected every token in
 * flight.
 *
 * <p><b>The discovery document kept deriving from the issuer through that change, which is the
 * defect this class exists to fix.</b> It advertised {@code jwks_uri} and {@code token_endpoint} on
 * a host that no longer resolves, so a consumer that had cached nothing — a service booting for the
 * first time — followed the document to an {@code UnknownHostException} and rolled back. A running
 * consumer never noticed, because its JWKS was already cached; only a fresh boot paid, which is why
 * this survived a working platform.
 *
 * <p>So: {@link #url()} is an IDENTIFIER and is compared, {@link #endpointBase()} is an ADDRESS and
 * is dialled. They are allowed to differ and on this platform they do. The one thing that must
 * still hold is that the {@code issuer} member of the discovery document and the {@code iss} of a
 * token are the same string, and both come from {@link #url()}.
 */
@ApplicationScoped
public class Issuer {

  @ConfigProperty(name = "qits.idp.issuer")
  String configured;

  /**
   * Where a consumer reaches this service, which is not necessarily what it is called.
   *
   * <p>Derived from the environment rather than stored as deployment configuration: an address that
   * follows one rule is code, and a config entry holding it is a second copy that goes stale
   * silently — as the issuer's did.
   */
  @ConfigProperty(name = "qits.idp.endpoint-base")
  String endpointBase;

  /** The issuer string: {@code qits.idp.issuer} trimmed, with any trailing slash removed. */
  public String url() {
    return trimmed(configured);
  }

  /**
   * The base every advertised endpoint hangs off: {@code qits.idp.endpoint-base}, normalised the
   * same way. Normalising once — here — is what keeps a configured trailing slash from becoming the
   * one character that breaks a URL.
   */
  public String endpointBase() {
    return trimmed(endpointBase);
  }

  /** {@code <endpointBase>/token} — derived, never separately configured. */
  public String tokenEndpoint() {
    return endpointBase() + "/token";
  }

  /** {@code <endpointBase>/authorize} — the Git workstation's Authorization Code + PKCE leg. */
  public String authorizationEndpoint() {
    return endpointBase() + "/authorize";
  }

  /** {@code <endpointBase>/jwks} — derived, never separately configured. */
  public String jwksUri() {
    return endpointBase() + "/jwks";
  }

  private static String trimmed(String value) {
    String url = value.trim();
    while (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }
    return url;
  }
}
