package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.TokenService.IssuedToken;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The token endpoint: {@code POST /idp/token}, {@code application/x-www-form-urlencoded}, RFC 6749
 * {@code client_credentials}.
 *
 * <p>This class does the wire work only — pulling the client's credentials out of whichever of the
 * two supported places they arrived in, and dressing the result as a token response. Who the client
 * is and what it may have is {@link TokenService}'s.
 *
 * <p>The path is relative to {@code quarkus.rest.path=/idp}. It is a cross-repo contract: every
 * consumer reaches it through the {@code token_endpoint} of the discovery document, which is
 * derived from the same issuer string, so the three cannot drift apart.
 */
@Path("/token")
public class IdpTokenController {

  private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
  private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
  private static final String GRANT_REFRESH_TOKEN = "refresh_token";

  @Inject TokenService tokenService;

  @Inject WorkstationCredentials workstations;

  @org.eclipse.microprofile.config.inject.ConfigProperty(name = "qits.idp.workstation.client-id")
  String workstationClientId;

  /**
   * Client authentication is {@code client_secret_basic} or {@code client_secret_post}, never both
   * in one request — RFC 6749 §2.3 forbids it, and accepting both would make which one was checked
   * a question.
   *
   * @param audienceParams zero or more {@code audience} values. Repeated parameters and one
   *     whitespace-separated value both work; naming none asks for the client's whole allowed list.
   */
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response token(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @FormParam("grant_type") String grantType,
      @FormParam("client_id") String clientIdParam,
      @FormParam("client_secret") String clientSecretParam,
      @FormParam("audience") List<String> audienceParams,
      @FormParam("code") String code,
      @FormParam("redirect_uri") String redirectUri,
      @FormParam("code_verifier") String codeVerifier,
      @FormParam("refresh_token") String refreshToken) {

    if (grantType == null || grantType.isBlank()) {
      throw OAuthException.invalidRequest("grant_type is required");
    }
    if (GRANT_AUTHORIZATION_CODE.equals(grantType)) {
      publicClient(clientIdParam, clientSecretParam, authorization);
      WorkstationCredentials.RefreshGrant grant =
          workstations.exchangeCode(code, redirectUri, codeVerifier);
      return tokenResponse(tokenService.workstation(grant.userId()), grant.refreshToken());
    }
    if (GRANT_REFRESH_TOKEN.equals(grantType)) {
      publicClient(clientIdParam, clientSecretParam, authorization);
      WorkstationCredentials.RefreshGrant grant = workstations.refresh(refreshToken);
      return tokenResponse(tokenService.workstation(grant.userId()), grant.refreshToken());
    }
    if (!GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
      throw OAuthException.unsupportedGrantType(
          "supported grants are client_credentials, authorization_code, and refresh_token");
    }

    BasicCredentials credentials = credentials(authorization, clientIdParam, clientSecretParam);
    return tokenResponse(
        tokenService.clientCredentials(
            credentials.clientId(), credentials.secret(), audiences(audienceParams)), null);
  }

  /** RFC 6749 §5.1 response, with a refresh token only for the workstation grants. */
  private static Response tokenResponse(IssuedToken issued, String refreshToken) {
    // LinkedHashMap so the response reads in the order RFC 6749 §5.1 lists the members.
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", issued.accessToken());
    body.put("token_type", "Bearer");
    body.put("expires_in", issued.expiresInSeconds());
    if (refreshToken != null) {
      body.put("refresh_token", refreshToken);
    }
    return Response.ok(body)
        // RFC 6749 §5.1: a token response is never cached, anywhere.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /** The public workstation client authenticates by PKCE, never by an empty or shared secret. */
  private void publicClient(String clientId, String secret, String authorization) {
    if (authorization != null && !authorization.isBlank()) {
      throw OAuthException.invalidRequest("the workstation public client must not use Authorization");
    }
    if (clientId == null || !workstationClientId.equals(clientId) || (secret != null && !secret.isBlank())) {
      throw OAuthException.invalidClient("the workstation public client is required");
    }
  }

  /**
   * The client's credentials, from the Authorization header or the form — not both, and at least
   * one. The header half is {@link BasicCredentials}, which the commission API reads too.
   */
  private static BasicCredentials credentials(
      String authorization, String clientIdParam, String clientSecretParam) {
    BasicCredentials basic = BasicCredentials.parse(authorization);
    boolean postPresent = clientIdParam != null && !clientIdParam.isBlank();
    if (basic != null && postPresent) {
      throw OAuthException.invalidRequest(
          "client credentials must be presented once, not both in the header and in the form");
    }
    if (basic != null) {
      return basic;
    }
    if (!postPresent) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return new BasicCredentials(clientIdParam, clientSecretParam);
  }

  /** Repeated {@code audience} parameters and whitespace-separated values both flatten to here. */
  private static List<String> audiences(List<String> params) {
    if (params == null || params.isEmpty()) {
      return List.of();
    }
    List<String> audiences = new ArrayList<>();
    for (String param : params) {
      if (param == null) {
        continue;
      }
      for (String audience : param.trim().split("\\s+")) {
        if (!audience.isEmpty()) {
          audiences.add(audience);
        }
      }
    }
    return List.copyOf(audiences);
  }
}
