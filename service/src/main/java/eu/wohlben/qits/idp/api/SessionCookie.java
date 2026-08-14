package eu.wohlben.qits.idp.api;

import io.vertx.ext.web.RoutingContext;
import java.time.Duration;
import java.util.Locale;

/**
 * The {@code qits-session} cookie: its name, its attributes, and the two lines this service ever
 * sends.
 *
 * <p><b>The header is built by hand rather than through {@code NewCookie}.</b> Every attribute here
 * is a decision somebody has to be able to read off one line, and the JAX-RS builder adds its own
 * ({@code Version=1}) and hides the rest behind a fluent API. What goes on the wire is:
 *
 * <pre>qits-session=&lt;value&gt;; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax</pre>
 *
 * <p>with {@code ; Secure} appended over https. Attribute by attribute:
 *
 * <ul>
 *   <li><b>HttpOnly</b> — no script reads it. The value is a bearer credential for the whole
 *       platform; a cross-site scripting bug on any page under this host would otherwise hand it
 *       over.
 *   <li><b>Path=/</b> — the cookie is not for the idp, it is for the edge, which introspects it on
 *       requests to every other segment. Scoping it to {@code /idp} would mean it never reaches the
 *       gate it exists for.
 *   <li><b>SameSite=Lax</b> — the cookie stays off cross-site POSTs, which is most of the CSRF
 *       answer; the rest is that every state-changing route here takes a JSON body, and a
 *       cross-site form cannot send one. Lax rather than Strict so that following a link into the
 *       platform from anywhere else still arrives logged in.
 *   <li><b>Secure, conditionally</b> — set when the request is https or a proxy says it was.
 *       Unconditionally would break the developer host outright: {@code http://localhost:8080} is
 *       a secure context by browser rule, which is what makes passkeys work there with no TLS, but
 *       it is still plain http and a {@code Secure} cookie would simply never be stored.
 *   <li><b>No Domain</b> — host-only, so the cookie belongs to the one host the browser surfaces
 *       live on and is not offered to a sibling name. The app vhosts (registry, mirror, githost)
 *       are machine planes with credentials of their own and have no use for it.
 *   <li><b>Max-Age</b> — the session's TTL, from the same value that stamps the row's deadline, so
 *       a browser never holds a cookie the store has already stopped honouring.
 * </ul>
 */
public final class SessionCookie {

  /** The cookie's name. The edge reads it by this spelling; so does every test here. */
  public static final String NAME = "qits-session";

  private static final String FORWARDED_PROTO = "X-Forwarded-Proto";

  private SessionCookie() {}

  /** The {@code Set-Cookie} line that opens a session. */
  public static String set(String value, Duration ttl, boolean secure) {
    return line(value, ttl.toSeconds(), secure);
  }

  /**
   * The {@code Set-Cookie} line that ends one: the same attributes, an empty value and {@code
   * Max-Age=0}. <b>The attributes have to match</b> — a browser replaces a cookie only when name,
   * path and domain agree, so a clearing line that forgot {@code Path=/} would leave the old cookie
   * in place beside a new empty one.
   */
  public static String clear(boolean secure) {
    return line("", 0, secure);
  }

  /**
   * Whether this request arrived over https.
   *
   * <p>Two sources, because the platform has two shapes: a direct TLS connection, and — the usual
   * one — a request the edge terminated TLS for and forwarded over plain http on qits-net. The
   * header is trusted for the same reason the rest of the identity contract is: qits-net is the
   * trusted plane, and a caller that could set {@code X-Forwarded-Proto} here is already inside it.
   * Getting it wrong costs a missing {@code Secure} flag, never a session.
   */
  public static boolean isSecure(RoutingContext ctx) {
    if (ctx == null) {
      return false;
    }
    if (ctx.request().isSSL()) {
      return true;
    }
    String forwarded = ctx.request().getHeader(FORWARDED_PROTO);
    // A proxy chain may forward a list; the first entry is the client's own hop.
    if (forwarded == null) {
      return false;
    }
    String first = forwarded.split(",")[0].trim().toLowerCase(Locale.ROOT);
    return "https".equals(first);
  }

  private static String line(String value, long maxAgeSeconds, boolean secure) {
    StringBuilder cookie = new StringBuilder(NAME).append('=').append(value);
    cookie.append("; Path=/");
    cookie.append("; Max-Age=").append(maxAgeSeconds);
    cookie.append("; HttpOnly");
    cookie.append("; SameSite=Lax");
    if (secure) {
      cookie.append("; Secure");
    }
    return cookie.toString();
  }
}
