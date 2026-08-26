package eu.wohlben.qits.idp.api;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
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

  /** The prefix that turns an allow-list entry into a one-label wildcard. */
  private static final String WILDCARD = "*.";

  @ConfigMapping(prefix = "qits.idp.browser-sso")
  interface Config {
    /** The one origin that serves login, registration, and WebAuthn. */
    @WithDefault("http://localhost:8080")
    String canonicalOrigin();

    /**
     * Authorities that are allowed to receive a browser after a successful ceremony.
     *
     * <p>An entry is either an exact authority (<code>dev.wohlben.eu</code>,
     * <code>localhost:8080</code>) or the one wildcard form <code>*.&lt;authority&gt;</code>, which
     * matches exactly one extra label in front of that authority and nothing else: with
     * <code>*.dev.wohlben.eu</code> the host <code>ci.dev.wohlben.eu</code> is allowed, while
     * <code>a.b.dev.wohlben.eu</code> and the bare <code>dev.wohlben.eu</code> are not. The port is
     * part of the authority, so <code>*.dev.localhost:8080</code> allows
     * <code>ci.dev.localhost:8080</code> and refuses <code>ci.dev.localhost:9090</code>. One
     * wildcard entry covers every per-service host of an environment.
     */
    @WithDefault("localhost:8080")
    List<String> browserHosts();

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
    LinkedHashSet<String> configured = new LinkedHashSet<>();
    LinkedHashSet<String> wildcards = new LinkedHashSet<>();
    for (String host : config.browserHosts()) {
      String entry = host == null ? null : host.strip();
      boolean wildcard = entry != null && entry.startsWith(WILDCARD);
      String authority = authority(wildcard ? entry.substring(WILDCARD.length()) : entry);
      if (authority == null) {
        continue;
      }
      if (wildcard) {
        wildcards.add(authority);
      } else {
        configured.add(authority);
      }
    }
    hosts = Set.copyOf(configured);
    wildcardHosts = Set.copyOf(wildcards);
    String canonicalAuthority = authority(canonical.getAuthority());
    if (canonicalAuthority == null || !allows(canonicalAuthority)) {
      throw new IllegalStateException(
          "qits.idp.browser-sso.browser-hosts must include the canonical origin's authority");
    }
    cookieDomain = domain(config.cookieDomain().orElse(null));
    // Where a visitor with no valid destination lands. The canonical origin stopped being the
    // platform's front door when the login moved onto its own host, so falling back to it would
    // strand a targetless login on the IdP's own SPA. The cookie parent domain is the platform's
    // apex by construction — the same installation fact, stated once — and the edge forwards its
    // `/` to the landing application. It only qualifies when the allow-list names it (a public
    // installation lists its apex; the local platform's cookie parent carries no port and is not
    // an entry), and the canonical origin stays the answer everywhere else.
    String parent = authority(cookieDomain);
    landing = parent != null && allows(parent) ? parent : canonicalAuthority;
  }

  /** The configured parent domain, or {@code null} for a host-only cookie. */
  String cookieDomain() {
    return cookieDomain;
  }

  /** A safe, absolute destination. A missing or refused host lands at the platform's front door. */
  String returnLocation(String requestedHost, String requestedPath) {
    String host = authority(requestedHost);
    if (host == null || !allows(host)) {
      host = landing;
    }
    return canonical.getScheme() + "://" + host + path(requestedPath);
  }

  /** Whether the allow-list names this authority, by an exact entry or a wildcard one. */
  boolean allows(String authority) {
    if (hosts.contains(authority)) {
      return true;
    }
    for (String parent : wildcardHosts) {
      int label = authority.length() - parent.length() - 1;
      // One label and one dot in front of the parent authority, and the port is part of both, so a
      // different port simply does not end with the parent.
      if (label > 0
          && authority.charAt(label) == '.'
          && authority.endsWith(parent)
          && authority.lastIndexOf('.', label - 1) < 0) {
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
