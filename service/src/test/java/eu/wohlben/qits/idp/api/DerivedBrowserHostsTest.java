package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

/**
 * That the derivation actually reaches the running application, which no unit test can say.
 *
 * <p>{@link DerivedBrowserHosts} is a {@code ConfigSourceFactory} registered through {@code
 * META-INF/services}, so the ONE way it can fail is silently: the file is not on the classpath, the
 * class name in it drifts, or a Quarkus upgrade stops loading factories, and every key simply falls
 * back to whatever else states it — which is now nothing. This asserts the two keys
 * quarkus-security-webauthn resolves for itself, and that {@link BrowserSso} agrees with them, so
 * the wiring is pinned rather than the arithmetic.
 *
 * <p>The values are the SHIPPED ones — no {@code QITS_DOMAIN} is stated in the suite — which is also
 * the local-default guard: {@code WebAuthnTestHardware} runs the real ceremony against these exact
 * strings and the emulated authenticator can use no others.
 */
@QuarkusTest
public class DerivedBrowserHostsTest {

  @Inject BrowserSso browserSso;

  @Test
  public void theWebAuthnPairIsComposedFromTheStatedDomainAndNothingElseStatesIt() {
    assertEquals(
        WebAuthnTestHardware.ORIGIN,
        ConfigProvider.getConfig().getValue(PlatformDomain.WEBAUTHN_ORIGINS, String.class));
    assertEquals(
        PlatformDomain.LOCAL,
        ConfigProvider.getConfig().getValue(PlatformDomain.WEBAUTHN_RP_ID, String.class));
    assertEquals(
        PlatformDomain.LOCAL,
        ConfigProvider.getConfig().getValue(PlatformDomain.DOMAIN, String.class));
  }

  @Test
  public void theBrowserBoundaryAgreesWithWhatTheExtensionWasHanded() {
    // The cross-check startup already made, asserted from outside: this application booted, so the
    // origin list named the canonical origin. Restating the equality keeps the reason visible.
    assertEquals(
        ConfigProvider.getConfig().getValue(PlatformDomain.WEBAUTHN_ORIGINS, String.class),
        browserSso.canonicalOrigin());
    assertEquals(WebAuthnTestHardware.ORIGIN, browserSso.canonicalOrigin());
  }
}
