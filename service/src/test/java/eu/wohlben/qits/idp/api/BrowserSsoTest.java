package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

  private static BrowserSso sso(String canonicalOrigin, String domain) {
    return sso(canonicalOrigin, Optional.empty(), domain);
  }

  private static BrowserSso sso(
      String canonicalOrigin, Optional<String> cookieDomain, String domain) {
    BrowserSso sso = new BrowserSso();
    sso.config =
        new BrowserSso.Config() {
          @Override
          public String canonicalOrigin() {
            return canonicalOrigin;
          }

          @Override
          public String domain() {
            return domain;
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
  public void theDerivedWildcardAllowsUpToThreeExtraLabels() {
    // One key, one domain. The list is <domain> and *.<domain>, and nothing else.
    BrowserSso sso = sso("https://idp.wohlben.eu", "wohlben.eu");

    // One label: an application on the platform's own domain.
    assertEquals("https://qits.wohlben.eu/", sso.returnLocation("qits.wohlben.eu", "/"));
    // Two: an application of a project, <app>.<project>.<domain>. This is the live bug — the
    // accreted list did not carry it, and a completed sign-in bounced back to the front door.
    assertEquals(
        "https://projects.qits.wohlben.eu/edit",
        sso.returnLocation("projects.qits.wohlben.eu", "/edit"));
    // Two the other way round, <env>.<project>.<domain>.
    assertEquals("https://dev.qits.wohlben.eu/", sso.returnLocation("dev.qits.wohlben.eu", "/"));
    // Three, the grammar's full depth: <app>.<env>.<project>.<domain>.
    assertEquals(
        "https://projects.dev.qits.wohlben.eu/",
        sso.returnLocation("projects.dev.qits.wohlben.eu", "/"));
    // Four is not a name the grammar can produce, so it falls back to the front door; only the
    // authority is replaced, the path was safe on its own.
    assertEquals(
        "https://idp.wohlben.eu/projects",
        sso.returnLocation("a.projects.dev.qits.wohlben.eu", "/projects"));
    // The exact entry names the domain itself, which the wildcard does not.
    assertEquals("https://wohlben.eu/", sso.returnLocation("wohlben.eu", "/"));
  }

  @Test
  public void aDifferentDomainIsRefusedHoweverItIsSpelled() {
    BrowserSso sso = sso("https://idp.wohlben.eu", "wohlben.eu");

    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("evil.example", "/"));
    // A foreign host that merely ends in the same labels is a different authority.
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("wohlben.eu.example", "/"));
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("qits.wohlben.eu.example", "/"));
    // And a name that merely ends in the same characters without a label boundary.
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("evilwohlben.eu", "/"));
    // Still no open redirect through the path either.
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("evil.example", "//evil.example"));
  }

  @Test
  public void theDerivedEntriesCarryTheCanonicalOriginsPort() {
    // The shipped local story: the domain is `localhost` and the canonical origin lends :8080.
    BrowserSso sso = sso("http://localhost:8080", "localhost");

    assertEquals("http://localhost:8080/", sso.returnLocation("localhost:8080", "/"));
    assertEquals("http://qits.localhost:8080/", sso.returnLocation("qits.localhost:8080", "/"));
    assertEquals(
        "http://projects.dev.qits.localhost:8080/",
        sso.returnLocation("projects.dev.qits.localhost:8080", "/"));
    // The port is part of the authority, so a mismatched or missing one is a different host, at
    // every depth.
    assertEquals("http://localhost:8080/", sso.returnLocation("qits.localhost:9090", "/"));
    assertEquals("http://localhost:8080/", sso.returnLocation("qits.localhost", "/"));
    assertEquals("http://localhost:8080/", sso.returnLocation("localhost", "/"));
    assertEquals(
        "http://localhost:8080/", sso.returnLocation("projects.dev.qits.localhost:9090", "/"));
  }

  @Test
  public void aTargetlessLoginLandsAtTheAllowListedCookieParentRatherThanTheIdpItself() {
    // The public shape: canonical is idp.<domain>, the cookie parent is the domain, and the domain
    // is the derived list's exact entry.
    BrowserSso sso = sso("https://idp.wohlben.eu", Optional.of("wohlben.eu"), "wohlben.eu");

    // No target at all — a typed login address — goes to the platform's front door, not the IdP.
    assertEquals("https://wohlben.eu/", sso.returnLocation(null, null));
    // A refused host falls back the same way.
    assertEquals("https://wohlben.eu/projects", sso.returnLocation("evil.example", "/projects"));
    // A listed host is still honoured verbatim, the IdP's own included.
    assertEquals("https://idp.wohlben.eu/", sso.returnLocation("idp.wohlben.eu", "/"));
  }

  @Test
  public void aCookieParentTheDerivedListDoesNotNameChangesNothing() {
    // The local platform: the cookie is host-only, so there is no parent to land at and the
    // canonical origin remains the fallback, exactly as before.
    BrowserSso sso = sso("http://localhost:8080", Optional.empty(), "localhost");

    assertEquals("http://localhost:8080/", sso.returnLocation(null, null));
    assertEquals("http://localhost:8080/", sso.returnLocation("evil.example", "/"));

    // And a parent that is a name UNDER the domain rather than the domain itself: allowed by the
    // wildcard, so it is where a targetless login lands.
    BrowserSso deeper =
        sso("https://idp.qits.wohlben.eu", Optional.of("qits.wohlben.eu"), "wohlben.eu");
    assertEquals("https://qits.wohlben.eu/", deeper.returnLocation(null, null));
  }

  @Test
  public void theProcessRefusesToStartWhenTheDerivationDoesNotCoverTheCanonicalOrigin() {
    // The ordinary case starts: the canonical origin is a name under the stated domain.
    assertEquals(
        "https://qits.wohlben.eu/",
        sso("https://idp.wohlben.eu", "wohlben.eu").returnLocation("qits.wohlben.eu", "/"));

    // A domain that does not cover the canonical origin is a misconfiguration of one of the two,
    // and the process refuses to start on it rather than issuing bounces nobody can return from.
    assertThrows(
        IllegalStateException.class, () -> sso("https://idp.wohlben.eu", "example.org"));
    // Including one that is merely too shallow for the canonical origin's own depth.
    assertThrows(
        IllegalStateException.class,
        () -> sso("https://a.projects.dev.qits.wohlben.eu", "wohlben.eu"));
    // A domain that is not an authority at all is refused in its own right.
    assertThrows(IllegalStateException.class, () -> sso("https://idp.wohlben.eu", ""));
    assertThrows(
        IllegalStateException.class, () -> sso("https://idp.wohlben.eu", "wohlben.eu/steal"));
  }
}
