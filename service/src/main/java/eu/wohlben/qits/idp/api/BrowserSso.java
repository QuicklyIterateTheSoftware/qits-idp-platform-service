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

  @ConfigMapping(prefix = "qits.idp.browser-sso")
  interface Config {
    /** The one origin that serves login, registration, and WebAuthn. */
    @WithDefault("http://localhost:8080")
    String canonicalOrigin();

    /** Authorities that are allowed to receive a browser after a successful ceremony. */
    @WithDefault("localhost:8080")
    List<String> browserHosts();

    /** Empty means a host-only session cookie; a domain deployment names its parent domain. */
    Optional<String> cookieDomain();
  }

  @jakarta.inject.Inject Config config;

  private URI canonical;
  private Set<String> hosts;
  private String cookieDomain;

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
    for (String host : config.browserHosts()) {
      String authority = authority(host);
      if (authority != null) {
        configured.add(authority);
      }
    }
    String canonicalAuthority = authority(canonical.getAuthority());
    if (configured.isEmpty() || canonicalAuthority == null || !configured.contains(canonicalAuthority)) {
      throw new IllegalStateException(
          "qits.idp.browser-sso.browser-hosts must include the canonical origin's authority");
    }
    hosts = Set.copyOf(configured);
    cookieDomain = domain(config.cookieDomain().orElse(null));
  }

  /** The configured parent domain, or {@code null} for a host-only cookie. */
  String cookieDomain() {
    return cookieDomain;
  }

  /** A safe, absolute destination. Invalid caller input lands at the canonical front door. */
  String returnLocation(String requestedHost, String requestedPath) {
    String host = authority(requestedHost);
    if (host == null || !hosts.contains(host)) {
      host = authority(canonical.getAuthority());
    }
    return canonical.getScheme() + "://" + host + path(requestedPath);
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
