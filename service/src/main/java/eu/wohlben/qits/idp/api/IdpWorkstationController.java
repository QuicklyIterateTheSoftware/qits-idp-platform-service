package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The browser leg of the Git workstation OAuth flow and the signed-in user's revocation surface.
 *
 * <p>{@code /authorize} is public in the OAuth sense — a local process can initiate it — but it
 * never approves a credential without a live {@code qits-session}. The API below it is not an OAuth
 * protocol endpoint and requires that same session for every request.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class IdpWorkstationController {

  private static final String RESPONSE_TYPE_CODE = "code";
  private static final String S256 = "S256";

  @Inject Sessions sessions;

  @Inject WorkstationCredentials workstations;

  @ConfigProperty(name = "qits.idp.workstation.client-id")
  String clientId;

  @ConfigProperty(name = "qits.idp.workstation.githost-audience")
  String githostAudience;

  /**
   * Approve a PKCE code for a local loopback listener and send it directly back to that listener.
   * The redirect URI is stored verbatim and must match byte-for-byte at token exchange.
   */
  @GET
  @Path("/authorize")
  public Response authorize(
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @QueryParam("response_type") String responseType,
      @QueryParam("client_id") String requestedClientId,
      @QueryParam("redirect_uri") String redirectUri,
      @QueryParam("code_challenge") String codeChallenge,
      @QueryParam("code_challenge_method") String challengeMethod,
      @QueryParam("audience") String audience,
      @QueryParam("state") String state) {
    Sessions.Live session =
        sessions
            .resolve(sessionToken)
            .orElseThrow(() -> AuthException.invalidCredentials("a signed-in session is required"));
    if (!RESPONSE_TYPE_CODE.equals(responseType)
        || !clientId.equals(requestedClientId)
        || !S256.equals(challengeMethod)
        || !githostAudience.equals(audience)) {
      throw OAuthException.invalidRequest("invalid workstation authorization request");
    }
    WorkstationCredentials.requireChallenge(codeChallenge);
    URI callback = loopbackRedirect(redirectUri);
    WorkstationCredentials.AuthorizationCode code =
        workstations.authorize(session.userId(), redirectUri, codeChallenge);
    UriBuilder response = UriBuilder.fromUri(callback).queryParam("code", code.value());
    if (state != null) {
      response.queryParam("state", state);
    }
    return Response.seeOther(response.build()).build();
  }

  /** List revocable workstation grants for the signed-in account. */
  @GET
  @Path("/api/workstations")
  public java.util.List<WorkstationCredentials.Workstation> list(
      @CookieParam(SessionCookie.NAME) String sessionToken) {
    return workstations.list(requireSession(sessionToken).userId());
  }

  /** Revoke a workstation grant. A foreign id is indistinguishable from no such grant. */
  @DELETE
  @Path("/api/workstations/{familyId}")
  public Response revoke(
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @jakarta.ws.rs.PathParam("familyId") UUID familyId) {
    if (!workstations.revoke(requireSession(sessionToken).userId(), familyId)) {
      throw OAuthException.notFound("workstation credential not found");
    }
    return Response.noContent().build();
  }

  private Sessions.Live requireSession(String sessionToken) {
    return sessions
        .resolve(sessionToken)
        .orElseThrow(() -> AuthException.invalidCredentials("a signed-in session is required"));
  }

  /**
   * OAuth loopback redirects are intentionally narrow: HTTP only, a numeric loopback IP, an
   * ephemeral listener port, no query/user-info/fragment. Restricting the host prevents an open
   * redirect while the exact original spelling remains bound to the authorization code.
   */
  private static URI loopbackRedirect(String raw) {
    if (raw == null || raw.isBlank()) {
      throw OAuthException.invalidRequest("redirect_uri is required");
    }
    try {
      URI uri = new URI(raw);
      String host = uri.getHost();
      boolean loopback = "127.0.0.1".equals(host) || "[::1]".equals(host) || "::1".equals(host);
      if (!"http".equals(uri.getScheme())
          || !loopback
          || uri.getPort() < 1
          || uri.getUserInfo() != null
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null
          || uri.getRawPath() == null
          || uri.getRawPath().isBlank()) {
        throw OAuthException.invalidRequest("redirect_uri must be an exact HTTP loopback callback");
      }
      return uri;
    } catch (URISyntaxException badUri) {
      throw OAuthException.invalidRequest("redirect_uri must be a URI");
    }
  }
}
