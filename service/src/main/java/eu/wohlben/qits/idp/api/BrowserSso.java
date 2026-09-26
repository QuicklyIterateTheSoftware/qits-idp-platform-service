package eu.wohlben.qits.idp.api;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.net.URI;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The public browser boundary of this installation.
 *
 * <p>The IdP is the only place a WebAuthn ceremony happens.  Environment hosts therefore send a
 * visitor here, and this class is also the final authority on where that visitor may be sent back.
 * Keeping the allow-list beside the cookie domain is intentional: both are installation facts, not
 * values a browser request may choose.
 */
@ApplicationScoped
public class BrowserSso {

  /**
   * How many labels a wildcard entry admits in front of its authority.
   *
   * <p>Three, because the platform's hostname grammar is
   * <code>&lt;app&gt;[.&lt;env&gt;].&lt;project&gt;.&lt;domain&gt;</code> read right to left, so
   * three labels in front of the domain is the deepest legal name there is. The bound is the
   * grammar's own depth rather than a number picked to fit today's hosts.
   */
  private static final int WILDCARD_LABELS = 3;

  @ConfigMapping(prefix = "qits.idp.browser-sso")
  interface Config {
    /** The one origin that serves login, registration, and WebAuthn. */
    @WithDefault("http://localhost:8080")
    String canonicalOrigin();

    /**
     * The platform's domain — the bootstrap's own <code>--domain</code> input, as
     * <code>QITS_DOMAIN</code> — and the sole source of the return-host allow-list.
     *
     * <p>The list is <em>derived</em>, not configured: it is the exact authority
     * <code>&lt;domain&gt;</code> plus the one wildcard <code>*.&lt;domain&gt;</code>, which admits
     * up to three labels in front. That is every name the hostname grammar
     * <code>&lt;app&gt;[.&lt;env&gt;].&lt;project&gt;.&lt;domain&gt;</code> can produce —
     * <code>qits.&lt;domain&gt;</code>, <code>projects.qits.&lt;domain&gt;</code>,
     * <code>dev.qits.&lt;domain&gt;</code> and
     * <code>projects.dev.qits.&lt;domain&gt;</code> — for every project and every environment,
     * without this service knowing one project or one environment name.
     *
     * <p>The port is part of an authority, so the canonical origin's port (where it has one) is
     * appended to the derived entries: locally the domain is <code>localhost</code> and the list
     * is <code>localhost:8080</code> and <code>*.localhost:8080</code>, which allows
     * <code>ci.dev.qits.localhost:8080</code> and refuses <code>ci.dev.qits.localhost:9090</code>.
     */
    @WithDefault("localhost")
    String domain();

    /** Empty means a host-only session cookie; a domain deployment names its parent domain. */
    Optional<String> cookieDomain();
  }

  @jakarta.inject.Inject Config config;

  private URI canonical;
  private Set<String> hosts;
  private Set<String> wildcardHosts;
  private String cookieDomain;
  private String landing;

  @PostConstruct
  void validate() {
    canonical = URI.create(config.canonicalOrigin().strip());
    if (!("http".equals(canonical.getScheme()) || "https".equals(canonical.getScheme()))
            || canonical.getHost() == null
            || canonical.getRawQuery() != null
            || canonical.getRawFragment() != null
            || !"".equals(canonical.getPath())) {
      throw new IllegalStateException(
          "qits.idp.browser-sso.canonical-origin must be an http(s) origin with no path, query, or fragment");
    }
    // The allow-list, derived from the stated domain and nothing else. Two entries: the domain
    // itself, and the wildcard over it, which WILDCARD_LABELS bounds at the grammar's own depth.
    // The port belongs to an authority, so a canonical origin that carries one lends it to both.
    String stated = config.domain() == null ? "" : config.domain().strip();
    String ported =
        !stated.isEmpty() && stated.indexOf(':') < 0 && canonical.getPort() >= 0
            ? stated + ":" + canonical.getPort()
            : stated;
    String domainAuthority = authority(ported);
    if (domainAuthority == null) {
      throw new IllegalStateException(
          "qits.idp.browser-sso.domain must be the platform's domain, as QITS_DOMAIN states it");
    }
    hosts = Set.of(domainAuthority);
    wildcardHosts = Set.of(domainAuthority);
    String canonicalAuthority = authority(canonical.getAuthority());
    // Cannot fail on a well-formed pair — the canonical origin is a name under the platform's own
    // domain — so it firing means the domain or the derivation is wrong, which is precisely when
    // starting anyway would be worse than not starting at all.
    if (canonicalAuthority == null || !allows(canonicalAuthority)) {
      throw new IllegalStateException(
          "the allow-list derived from qits.idp.browser-sso.domain must include the canonical"
              + " origin's authority");
    }
    cookieDomain = domain(config.cookieDomain().orElse(null));
    // Where a visitor with no valid destination lands. The canonical origin stopped being the
    // platform's front door when the login moved onto its own host, so falling back to it would
    // strand a targetless login on the IdP's own SPA. The cookie parent domain is the platform's
    // apex by construction — the same installation fact, stated once — and the edge forwards its
    // `/` to the landing application. It only qualifies when the derived list names it (a public
    // installation's cookie parent IS the stated domain, so the exact entry is it; the local
    // platform is host-only and names no parent at all), and the canonical origin stays the answer
    // everywhere else.
    String parent = authority(cookieDomain);
    landing = parent != null && allows(parent) ? parent : canonicalAuthority;
  }

  /** The configured parent domain, or {@code null} for a host-only cookie. */
  String cookieDomain() {
    return cookieDomain;
  }

  /**
   * The origin a browser actually reaches this idp on — scheme and authority, no trailing slash.
   *
   * <p><b>Not the issuer.</b> {@code qits.idp.issuer} is the address services dial over the
   * platform network ({@code http://qits-platform-idp:8080/idp} in every deployment shipped so
   * far), and no browser can resolve that name. Anything a person's browser is sent to — the
   * sign-in bounce, and the CLI code page a {@code redirect_uri} may name — is built from this
   * instead. It is configuration either way, which is the property that matters: neither is taken
   * from the request.
   */
  String canonicalOrigin() {
    return canonical.getScheme() + "://" + canonicalAuthority();
  }

  /** The canonical origin's authority — validated at startup to be on the allow-list. */
  String canonicalAuthority() {
    return authority(canonical.getAuthority());
  }

  /** A safe, absolute destination. A missing or refused host lands at the platform's front door. */
  String returnLocation(String requestedHost, String requestedPath) {
    String host = authority(requestedHost);
    if (host == null || !allows(host)) {
      host = landing;
    }
    return canonical.getScheme() + "://" + host + path(requestedPath);
  }

  /**
   * Whether the allow-list names this authority, by an exact entry or a wildcard one.
   *
   * <p>A wildcard entry admits <b>up to three</b> labels in front of its authority, which is the
   * whole of the platform's hostname grammar,
   * <code>&lt;app&gt;[.&lt;env&gt;].&lt;project&gt;.&lt;domain&gt;</code>:
   * <code>qits.&lt;domain&gt;</code> (one), <code>projects.qits.&lt;domain&gt;</code> and
   * <code>dev.qits.&lt;domain&gt;</code> (two), <code>projects.dev.qits.&lt;domain&gt;</code>
   * (three). A fourth label is not a name the grammar can produce, so it is refused. The bound
   * stays a number rather than becoming a plain suffix match, so the rule remains something a
   * reader can check by counting dots.
   *
   * <p><b>Why the extra labels are safe.</b> The single wildcard entry this installation carries is
   * derived from the platform's own domain — {@code qits.idp.browser-sso.domain}, the bootstrap's
   * {@code QITS_DOMAIN} — and the platform's DNS zone points <code>*</code>, <code>*.*</code> and
   * <code>*.*.*</code> at the platform's own edge, where a name no vhost claims answers 404. So
   * every authority an extra label can add resolves to this platform and to nothing else: the
   * widening is across platform-served names, not towards a foreign host, and it opens no redirect.
   * What keeps that true is the anchor, not the label count — the entry's parent authority is a
   * suffix match, so an extra label can only ever reach deeper <em>under</em> a name the one-label
   * rule already admitted. An entry whose parent is not the platform's own domain would already
   * have been an open door at one label; the derivation cannot produce one.
   */
  boolean allows(String authority) {
    if (hosts.contains(authority)) {
      return true;
    }
    for (String parent : wildcardHosts) {
      int label = authority.length() - parent.length() - 1;
      // The dot in front of the parent authority. The port is part of both, so a different port
      // simply does not end with the parent.
      if (label <= 0 || authority.charAt(label) != '.' || !authority.endsWith(parent)) {
        continue;
      }
      // Then count the dots in what is left, refusing an empty label either side of one.
      int labels = 1;
      int dot = authority.lastIndexOf('.', label - 1);
      while (dot > 0 && dot < label - 1 && labels < WILDCARD_LABELS) {
        labels++;
        label = dot;
        dot = authority.lastIndexOf('.', label - 1);
      }
      if (dot < 0) {
        return true;
      }
    }
    return false;
  }

  static String path(String raw) {
    if (raw == null || raw.isBlank()) {
      return "/";
    }
    for (int i = 0; i < raw.length(); i++) {
      char character = raw.charAt(i);
      if (character < 0x20 || character == 0x7f) {
        return "/";
      }
    }
    return raw.startsWith("/") && !raw.startsWith("//") && !raw.startsWith("/\\")
        ? raw
        : "/";
  }

  /** A lower-case host with an optional non-default port, or null when it is not an authority. */
  static String authority(String raw) {
    if (raw == null || raw.isBlank() || raw.indexOf('/') >= 0 || raw.indexOf('\\') >= 0) {
      return null;
    }
    try {
      URI parsed = URI.create("https://" + raw.strip());
      if (parsed.getHost() == null
          || parsed.getUserInfo() != null
          || parsed.getPath().length() != 0
          || parsed.getRawQuery() != null
          || parsed.getRawFragment() != null) {
        return null;
      }
      String host = parsed.getHost().toLowerCase(Locale.ROOT);
      return parsed.getPort() < 0 ? host : host + ":" + parsed.getPort();
    } catch (IllegalArgumentException invalid) {
      return null;
    }
  }

  private static String domain(String raw) {
    if (raw == null || raw.isBlank()) {
      return null;
    }
    String value = raw.strip().toLowerCase(Locale.ROOT);
    if (!value.matches("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")) {
      throw new IllegalStateException(
          "qits.idp.browser-sso.cookie-domain must be a parent DNS domain, or empty for host-only");
    }
    return value;
  }
}
