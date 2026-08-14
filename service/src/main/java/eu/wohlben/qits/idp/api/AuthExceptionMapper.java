package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.error.AuthException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps the user surface's {@link AuthException} to its response — the sibling of {@link
 * OAuthExceptionMapper}, and deliberately not the same one.
 *
 * <p>The body reads identically ({@code error}, {@code error_description}) so that a client has one
 * shape to parse across this whole service. <b>What it does not carry is {@code WWW-Authenticate}.</b>
 * These routes are called by a browser with {@code fetch}, and a Basic challenge on a failed login
 * is at best noise and at worst a native credentials dialog appearing in front of the login page —
 * which is the opposite of what the 401 is for. The machine surfaces next door still send it,
 * because a Basic pair is genuinely what they want back.
 */
@Provider
public class AuthExceptionMapper implements ExceptionMapper<AuthException> {

  @Override
  public Response toResponse(AuthException exception) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", exception.error());
    body.put("error_description", exception.getMessage());

    return Response.status(exception.statusCode())
        .entity(body)
        .type(MediaType.APPLICATION_JSON)
        // Nothing on this surface is cacheable: the bodies describe a credential's fate.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }
}
