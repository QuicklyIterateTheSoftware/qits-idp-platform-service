package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The return-host allow-list, which is the only thing standing between a public query string and an
 * open redirect.
 *
 * <p>No application start: the rules are pure, and reading them here keeps every case — including
 * the ones that must be refused — in one short file.
 */
public class BrowserSsoTest {

  private static BrowserSso sso(String canonicalOrigin, String... browserHosts) {
    return sso(canonicalOrigin, Optional.empty(), browserHosts);
  }

  private static BrowserSso sso(
      String canonicalOrigin, Optional<String> cookieDomain, String... browserHosts) {
    BrowserSso sso = new BrowserSso();
    sso.config =
        new BrowserSso.Config() {
          @Override
          public String canonicalOrigin() {
            return canonicalOrigin;
          }

          @Override
          public List<String> browserHosts() {
            return List.of(browserHosts);
          }

          @Override
          public Optional<String> cookieDomain() {
            return cookieDomain;
          }
        };
    sso.validate();
    return sso;
  }

  @Test
  public void aWildcardEntryAllowsExactlyOneExtraLabel() {
    BrowserSso sso =
        sso("https://wohlben.eu", "wohlben.eu", "dev.wohlben.eu", "*.dev.wohlben.eu");

    // One extra label: every per-service host of the environment, from one entry.
    assertEquals(
        "https://ci.dev.wohlben.eu/projects",
        sso.returnLocation("ci.dev.wohlben.eu", "/projects"));
    // Two labels deep is not the environment's own host and falls back to the front door; only the
    // authority is replaced, the path was safe on its own.
    assertEquals("https://wohlben.eu/projects", sso.returnLocation("a.b.dev.wohlben.eu", "/projects"));
    // The wildcard does not name its own parent; the exact entry beside it does.
    assertEquals("https://dev.wohlben.eu/", sso.returnLocation("dev.wohlben.eu", "/"));
    assertEquals("https://wohlben.eu/", sso.returnLocation("evil.example", "/"));
  }

  @Test
  public void theWildcardParentCarriesItsPort() {
    BrowserSso sso = sso("http://dev.localhost:8080", "dev.localhost:8080", "*.dev.localhost:8080");

    assertEquals("http://ci.dev.localhost:8080/", sso.returnLocation("ci.dev.localhost:8080", "/"));
    // A host that matches by name but not by port is a different authority.
    assertEquals("http://dev.localhost:8080/", sso.returnLocation("ci.dev.localhost:9090", "/"));
    assertEquals("http://dev.localhost:8080/", sso.returnLocation("ci.dev.localhost", "/"));
  }

  @Test
  public void exactEntriesStillDecideAlone() {
    BrowserSso sso = sso("http://localhost:8080", "localhost:8080", "dev.wohlben.eu");

    assertEquals(
        "http://dev.wohlben.eu/projects/7?tab=runs",
        sso.returnLocation("dev.wohlben.eu", "/projects/7?tab=runs"));
    assertEquals("http://localhost:8080/", sso.returnLocation("ci.dev.wohlben.eu", "/"));
    // Still no open redirect through the path either.
    assertEquals("http://localhost:8080/", sso.returnLocation("evil.example", "//evil.example"));
  }

  @Test
  public void aTargetlessLoginLandsAtTheAllowListedCookieParentRatherThanTheIdpItself() {
    // The public shape since the login moved onto its own host: canonical is idp.<domain>, the
    // cookie parent is the apex, and the apex is an allow-list entry.
    BrowserSso sso =
        sso("https://idp.wohlben.eu", Optional.of("wohlben.eu"), "wohlben.eu", "*.wohlben.eu");

    // No target at all — a typed login address — goes to the platform's front door, not the IdP.
    assertEquals("https://wohlben.eu/", sso.returnLocation(null, null));
    // A refused host falls back the same way.
    assertEquals("https://wohlben.eu/projects", sso.returnLocation("evil.example", "/projects"));
    // A listed host is still honoured verbatim, the IdP's own included.
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("idp.wohlben.eu", "/"));
  }

  @Test
  public void aCookieParentTheAllowListDoesNotNameChangesNothing() {
    // The local platform: the cookie parent carries no port, so it is not a listed authority and
    // the canonical origin remains the fallback, exactly as before.
    BrowserSso sso =
        sso(
            "http://dev.localhost:8080",
            Optional.of("dev.localhost"),
            "dev.localhost:8080",
            "*.dev.localhost:8080");

    assertEquals("http://dev.localhost:8080/", sso.returnLocation(null, null));
    assertEquals("http://dev.localhost:8080/", sso.returnLocation("evil.example", "/"));
  }

  @Test
  public void aWildcardEntryMayCoverTheCanonicalOriginItself() {
    assertEquals(
        "https://ci.dev.wohlben.eu/",
        sso("https://dev.wohlben.eu", "*.wohlben.eu", "*.dev.wohlben.eu")
            .returnLocation("ci.dev.wohlben.eu", "/"));
    // An allow-list that names neither the canonical authority nor a parent of it is a
    // misconfiguration, and the process refuses to start on it.
    assertThrows(
        IllegalStateException.class, () -> sso("https://dev.wohlben.eu", "*.dev.wohlben.eu"));
  }
}
