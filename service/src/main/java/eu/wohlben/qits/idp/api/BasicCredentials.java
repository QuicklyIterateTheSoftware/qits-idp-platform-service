package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.error.OAuthException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * A client id and secret out of an HTTP {@code Authorization: Basic} header.
 *
 * <p>Spelled once, because both surfaces read it: the token endpoint's {@code client_secret_basic}
 * (RFC 6749 §2.3.1) and the commission API, which accepts nothing else. A second parser would be a
 * second set of edge cases on the same credential.
 *
 * @param clientId the id, form-decoded
 * @param secret the secret, form-decoded
 */
public record BasicCredentials(String clientId, String secret) {

  private static final String BASIC_PREFIX = "basic ";

  /**
   * The credentials in this header, or null when the header is absent or is not Basic.
   *
   * <p>A <b>malformed</b> Basic header is a refusal rather than a null: a caller must not be able
   * to hide a bad header behind good credentials presented some other way.
   *
   * <p>Both halves are form-urlencoded before the base64 (RFC 6749 §2.3.1) and are decoded back
   * here, which is what makes a secret containing {@code :} or {@code +} work. A client that did
   * not encode is unaffected — the ids and secrets this service issues contain nothing that
   * encodes.
   *
   * @throws OAuthException {@code invalid_client} (401) when the header is Basic and unreadable
   */
  public static BasicCredentials parse(String authorizationHeader) {
    if (authorizationHeader == null
        || !authorizationHeader.toLowerCase(Locale.ROOT).startsWith(BASIC_PREFIX)) {
      return null;
    }
    String decoded;
    try {
      decoded =
          new String(
              Base64.getDecoder()
                  .decode(authorizationHeader.substring(BASIC_PREFIX.length()).trim()),
              StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      throw OAuthException.invalidClient("malformed Basic credentials");
    }
    int separator = decoded.indexOf(':');
    if (separator < 0) {
      throw OAuthException.invalidClient("malformed Basic credentials");
    }
    return new BasicCredentials(
        formDecode(decoded.substring(0, separator)), formDecode(decoded.substring(separator + 1)));
  }

  private static String formDecode(String value) {
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException | IllegalArgumentException e) {
      // A value that is not valid percent-encoding is taken as-is: it is then simply not the
      // configured secret, and the request fails as an authentication failure rather than a 500.
      return value;
    }
  }
}
