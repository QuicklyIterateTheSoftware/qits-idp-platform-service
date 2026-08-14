package eu.wohlben.qits.idp.api;

import io.quarkus.test.security.webauthn.WebAuthnHardware;
import io.vertx.core.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URI;

/**
 * An emulated authenticator, wrapped so that the two facts a test has to get right are stated once.
 *
 * <p>quarkus-test-security-webauthn's {@link WebAuthnHardware} holds a real EC keypair and produces
 * real attestations and assertions — which is what makes the ceremony in these tests genuine rather
 * than a recorded fixture. Two things about it are not free to choose:
 *
 * <ul>
 *   <li><b>The origin has to be a configured one.</b> webauthn4j checks the {@code origin} inside
 *       the browser's own {@code clientDataJSON} against {@code quarkus.webauthn.origins} — and
 *       against nothing else, in particular not against the port the request actually arrived on.
 *       So this says {@code http://localhost:8080}, the value this service <b>ships</b>, and the
 *       suite therefore tests the shipped default rather than an override written for it. That it
 *       works while the suite listens on a random port is the point: {@code
 *       quarkus.http.test-port=0} and the origin list are independent.
 *   <li><b>The relying party has to be {@code localhost}.</b> {@link WebAuthnHardware} hashes that
 *       string into its authenticator data with no way to change it, so {@code
 *       quarkus.webauthn.relying-party.id} must be the same — which the shipped default is. A
 *       deployment overriding it with {@code QITS_IDP_WEBAUTHN_RP_ID} is exactly the case this
 *       suite cannot cover, and a passkey being bound to its rp id is the reason it does not have
 *       to: users are per-installation by decision.
 * </ul>
 */
public class WebAuthnTestHardware {

  /** The one origin the shipped configuration accepts. See the class comment. */
  static final String ORIGIN = "http://localhost:8080";

  private final WebAuthnHardware hardware;

  public WebAuthnTestHardware() {
    try {
      hardware = new WebAuthnHardware(URI.create(ORIGIN).toURL());
    } catch (MalformedURLException e) {
      throw new IllegalStateException("the fixed test origin does not parse", e);
    }
  }

  /**
   * What {@code navigator.credentials.create()} would resolve to for this challenge — the object
   * the client posts as the {@code attestation} member.
   */
  public JsonObject registration(String challenge) {
    return hardware.makeRegistrationJson(challenge);
  }

  /**
   * What {@code navigator.credentials.get()} would resolve to — the {@code assertion} member.
   *
   * <p>Each call advances the authenticator's signature counter, which is deliberate: a counter
   * that did not move is a cloned authenticator and webauthn4j refuses the login, so a suite that
   * replayed one value would be proving the check is off.
   */
  public JsonObject assertion(String challenge) {
    return hardware.makeLoginJson(challenge);
  }
}
