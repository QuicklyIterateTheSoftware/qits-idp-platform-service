package eu.wohlben.qits.idp.control;

import java.util.regex.Pattern;

/**
 * What may be written to the log when a client id is named there.
 *
 * <p>A {@code client_id} arrives on an unauthenticated request, and a refusal logs it — which makes
 * the log a place an attacker can write. Everything outside the shape below becomes one fixed
 * token, so a control character, a newline or a megabyte cannot reach a log line through this
 * service.
 */
public final class LoggableClientId {

  /** The shape every id this service issues or configures has; anything else is somebody's probe. */
  private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._-]{1,128}");

  private LoggableClientId() {}

  /** {@code clientId} if it is safe to write, otherwise {@code <malformed>}. */
  public static String of(String clientId) {
    return clientId != null && SAFE.matcher(clientId).matches() ? clientId : "<malformed>";
  }
}
