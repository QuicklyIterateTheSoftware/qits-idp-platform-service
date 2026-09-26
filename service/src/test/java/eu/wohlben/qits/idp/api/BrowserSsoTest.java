package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The browser boundary composed from one stated domain, and the return-host allow-list — which is
 * the only thing standing between a public query string and an open redirect.
 *
 * <p>No application start: the rules are pure, and reading them here keeps every case — including
 * the ones that must be refused — in one short file. What the running application actually resolves
 * the derived config keys to is {@link DerivedBrowserHostsTest}'s job.
 */
public class BrowserSsoTest {

  /** The domain, and the WebAuthn origin list the derivation itself would publish for it. */
  private static BrowserSso sso(String domain) {
    return sso(domain, List.of(PlatformDomain.canonicalOrigin(PlatformDomain.stated(domain))));
  }

  private static BrowserSso sso(String domain, List<String> webAuthnOrigins) {
    BrowserSso sso = new BrowserSso();
    sso.config = () -> domain;
    sso.webAuthnOrigins = Optional.of(webAuthnOrigins);
    sso.validate();
    return sso;
  }

  @Test
  public void everyBrowserFacingNameComesOutOfTheOneStatedDomain() {
    // The public installation: this application's own host label, under the platform's own project
    // slug, under the stated domain — the platform's hostname grammar applied to the idp like to
    // anything else, and env-less because the `qits` project is.
    BrowserSso sso = sso("wohlben.eu");
    assertEquals("https://idp.qits.wohlben.eu", sso.canonicalOrigin());
    assertEquals("idp.qits.wohlben.eu", sso.canonicalAuthority());
    // The cookie spans the apex and every host under it, so one login is shared across the estate.
    assertEquals("wohlben.eu", sso.cookieDomain());
    // The relying party is the apex, FLAT — no host label and no project slug. See
    // PlatformDomain.relyingPartyId for why there is no override to pin it across a domain change.
    assertEquals("wohlben.eu", PlatformDomain.relyingPartyId("wohlben.eu"));

    // A stated domain is not case-sensitive and is not required to be tidy.
    assertEquals("https://idp.qits.wohlben.eu", sso(" WOHLBEN.EU ").canonicalOrigin());
  }

  @Test
  public void withNoDomainStatedTheDerivationIsStillTheShippedDeveloperHost() {
    // THE LOCAL DEFAULT MUST NOT MOVE. `localhost` is a secure context over plain http by browser
    // rule, nothing on a developer's machine resolves idp.qits.localhost, and the emulated
    // authenticator in WebAuthnTestHardware hard-hashes `localhost` as its relying party with no way
    // to change it — so a longer local name would take the real ceremony out of the suite.
    BrowserSso sso = sso(PlatformDomain.LOCAL);
    assertEquals("http://localhost:8080", sso.canonicalOrigin());
    assertEquals("localhost", PlatformDomain.relyingPartyId(PlatformDomain.LOCAL));
    assertEquals(WebAuthnTestHardware.ORIGIN, sso.canonicalOrigin());
    // And no cookie parent: a single-label host has none, and a browser refuses Domain=localhost.
    assertNull(sso.cookieDomain());
  }

  @Test
  public void theDerivedWildcardAllowsUpToThreeExtraLabels() {
    // One domain. The list is <domain> and *.<domain>, and nothing else.
    BrowserSso sso = sso("wohlben.eu");

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
        "https://wohlben.eu/projects",
        sso.returnLocation("a.projects.dev.qits.wohlben.eu", "/projects"));
    // The exact entry names the domain itself, which the wildcard does not.
    assertEquals("https://wohlben.eu/", sso.returnLocation("wohlben.eu", "/"));
    // And the idp's own derived host is on the list, which startup insists on.
    assertEquals("https://idp.qits.wohlben.eu/", sso.returnLocation("idp.qits.wohlben.eu", "/"));
  }

  @Test
  public void aDifferentDomainIsRefusedHoweverItIsSpelled() {
    BrowserSso sso = sso("wohlben.eu");

    assertEquals("https://wohlben.eu/", sso.returnLocation("evil.example", "/"));
    // A foreign host that merely ends in the same labels is a different authority.
    assertEquals("https://wohlben.eu/", sso.returnLocation("wohlben.eu.example", "/"));
    assertEquals("https://wohlben.eu/", sso.returnLocation("qits.wohlben.eu.example", "/"));
    // And a name that merely ends in the same characters without a label boundary.
    assertEquals("https://wohlben.eu/", sso.returnLocation("evilwohlben.eu", "/"));
    // Still no open redirect through the path either.
    assertEquals("https://wohlben.eu/", sso.returnLocation("evil.example", "//evil.example"));
  }

  @Test
  public void theDerivedEntriesCarryTheCanonicalOriginsPort() {
    // The shipped local story: the domain is `localhost` and the canonical origin lends :8080.
    BrowserSso sso = sso("localhost");

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
  public void aTargetlessLoginLandsAtTheDerivedCookieParentRatherThanTheIdpItself() {
    // The public shape: canonical is idp.qits.<domain>, the cookie parent is the domain, and the
    // domain is the derived list's exact entry — all three out of the same value.
    BrowserSso sso = sso("wohlben.eu");

    // No target at all — a typed login address — goes to the platform's front door, not the IdP.
    assertEquals("https://wohlben.eu/", sso.returnLocation(null, null));
    // A refused host falls back the same way.
    assertEquals("https://wohlben.eu/projects", sso.returnLocation("evil.example", "/projects"));
  }

  @Test
  public void aHostOnlyCookieLeavesTheCanonicalOriginAsTheFallback() {
    // The local platform: the cookie is host-only, so there is no parent to land at and the
    // canonical origin remains the fallback, exactly as before.
    BrowserSso sso = sso("localhost");

    assertEquals("http://localhost:8080/", sso.returnLocation(null, null));
    assertEquals("http://localhost:8080/", sso.returnLocation("evil.example", "/"));
  }

  @Test
  public void theProcessRefusesToStartWhenTheDerivationDoesNotCoverTheCanonicalOrigin() {
    // The guard is kept although both sides now come from one value: the canonical origin is a name
    // under the stated domain by construction, so this can only fire when the DOMAIN is wrong —
    // which is exactly when issuing bounces nobody can return from would be worse than not starting.
    assertTrue(sso("wohlben.eu").allows(sso("wohlben.eu").canonicalAuthority()));

    // A domain that is not a domain is refused in its own right, rather than composing an origin
    // out of it.
    assertThrows(IllegalStateException.class, () -> sso(""));
    assertThrows(IllegalStateException.class, () -> sso("   "));
    // And anything a stated value could smuggle into the concatenation — a path, a query, a second
    // authority — surfaces as an origin that is not one.
    assertThrows(IllegalStateException.class, () -> sso("wohlben.eu/steal"));
    assertThrows(IllegalStateException.class, () -> sso("wohlben.eu?x=1"));
    assertThrows(IllegalStateException.class, () -> sso("wohlben.eu/"));
  }

  @Test
  public void theProcessRefusesToStartWhenTheWebAuthnOriginsDoNotNameTheCanonicalOrigin() {
    // THE CROSS-CHECK. webauthn4j compares the origin inside the browser's own clientDataJSON
    // against quarkus.webauthn.origins and against nothing else, so a list that does not name the
    // origin a browser actually loaded fails every ceremony closed — registration and login alike —
    // with no configuration error logged anywhere. Both sides are derived from the same domain now,
    // which is why this should be impossible and why it is worth asserting rather than assuming.
    assertThrows(
        IllegalStateException.class,
        () -> sso("wohlben.eu", List.of("https://idp.dev.qits.wohlben.eu")));
    // The stale spelling this whole change exists to delete, and the empty list, refused alike.
    assertThrows(IllegalStateException.class, () -> sso("wohlben.eu", List.of()));
    assertThrows(
        IllegalStateException.class, () -> sso(PlatformDomain.LOCAL, List.of("http://localhost")));

    // A list that names the origin among others is fine: the check is membership, not identity.
    assertEquals(
        "https://idp.qits.wohlben.eu",
        sso("wohlben.eu", List.of("https://elsewhere.example", "https://idp.qits.wohlben.eu"))
            .canonicalOrigin());
  }
}
