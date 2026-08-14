package eu.wohlben.qits.idp.error;

/**
 * A refusal from the <b>user</b> surface — register, login, logout, password.
 *
 * <p><b>Why this is not {@link OAuthException}.</b> The two error shapes look alike on purpose, but
 * they answer different callers. {@code OAuthException} is RFC 6749's, and its mapper attaches
 * {@code WWW-Authenticate: Basic} to every 401 because the machine surfaces next door
 * authenticate with a Basic pair. These routes are called by a browser with {@code fetch}: a Basic
 * challenge there is at best noise and at worst a native credentials dialog in front of the login
 * page. So the codes are the same idea in a different vocabulary, and the mapper for this one sends
 * no challenge.
 *
 * <p><b>There are exactly two codes, and that is the point.</b> {@code invalid_credentials} covers
 * every way an authentication can fail — no session, an expired one, a spent register token, an
 * unknown username, a wrong password, an assertion that did not verify. A caller learns that it did
 * not authenticate and nothing else; which of the six happened lives in the log. Anything a caller
 * can fix by sending a different body — a missing field, a blank password, a username already taken
 * — is {@code invalid_request} instead, because telling somebody who already holds a register token
 * that their chosen name is taken is help, not a leak.
 *
 * <p>Framework-free like its sibling: the HTTP response is assembled in {@code service}.
 */
public class AuthException extends RuntimeException {

  private final String error;
  private final int statusCode;

  private AuthException(String error, int statusCode, String description) {
    super(description);
    this.error = error;
    this.statusCode = statusCode;
  }

  /** The {@code error} member of the response body. */
  public String error() {
    return error;
  }

  public int statusCode() {
    return statusCode;
  }

  /** The body was unusable, or asked for something the store will not accept. */
  public static AuthException invalidRequest(String description) {
    return new AuthException("invalid_request", 400, description);
  }

  /**
   * Authentication failed. One code for every cause — see the class comment; the description is
   * written for the operator reading the log, not for the caller to branch on.
   */
  public static AuthException invalidCredentials(String description) {
    return new AuthException("invalid_credentials", 401, description);
  }
}
