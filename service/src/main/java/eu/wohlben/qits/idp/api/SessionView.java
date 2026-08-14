package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Sessions;
import java.util.List;

/**
 * What a live session says about itself — the answer to a register, a login, and an introspection
 * alike.
 *
 * <p><b>One shape for the browser and for the edge, on purpose.</b> The edge introspects a cookie
 * to build {@code X-Qits-User}, {@code X-Qits-User-Id} and {@code X-Qits-Roles}; the client draws a
 * header from exactly the same four fields. Two shapes would be two places for the role list to
 * drift.
 *
 * <p>{@code expiresAt} is an ISO-8601 instant as a string rather than a number of seconds: the edge
 * caches this answer and has to know when it stops being true regardless of when it asked, and a
 * string that reads as a date in a log is worth more than one that has to be converted first.
 */
public record SessionView(String userId, String username, List<String> roles, String expiresAt) {

  static SessionView of(Sessions.Live session) {
    return new SessionView(
        session.userId().toString(),
        session.username(),
        session.roles(),
        session.expiresAt().toString());
  }
}
