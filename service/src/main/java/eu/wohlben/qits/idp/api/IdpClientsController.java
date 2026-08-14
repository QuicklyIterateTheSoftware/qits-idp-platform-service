package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClientRegistry;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.DynamicClients.Commissioned;
import eu.wohlben.qits.idp.control.DynamicClients.StoredClient;
import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The commission API: {@code /idp/api/clients}, where a service that provisions a dynamic context
 * gets a credential for it and gives it back when the context ends.
 *
 * <p>Three verbs and no more. {@code POST} commissions, {@code DELETE} decommissions, {@code GET}
 * lists what the caller commissioned so a crash cannot leak credentials nobody can see. The
 * lifetime model is in {@link DynamicClients}; this class is the boundary.
 *
 * <h2>Why HTTP Basic against the existing clients</h2>
 *
 * <p>A caller here is a platform service that <b>already holds its own idp client id and secret</b>
 * — that is how it gets tokens at all. Checking that pair directly is therefore the mechanism that
 * adds nothing: no new audience to configure, no bearer-validation stack in the service that issues
 * the bearers (the idp validating its own tokens would be a circular boot dependency the moment the
 * signing key load and the commission call meet), and no second credential for a deployment to
 * distribute. It is the same {@code client_secret_basic} the token endpoint already accepts, read
 * by the same {@link BasicCredentials} parser and checked by the same {@link ClientRegistry}, so
 * there is exactly one answer in this service to "is this who it says it is".
 *
 * <p>A token-based guard would be the right call the day these endpoints need per-caller
 * permissions beyond "is it a service client" — that is the same day per-context scoping lands, and
 * it can bring its own audience then.
 *
 * <p><b>Only a static service client may commission.</b> A commissioned credential authenticates
 * here (it has to, so a context can hand its own credential back), but {@code POST} refuses it:
 * a credential that could commission more credentials would outlive its own decommission through
 * the ones it made, and the blast radius of a leaked build-step secret would stop being one build.
 *
 * <p><b>These routes are reachable through the gateway</b>, which routes {@code /idp/*} verbatim.
 * They are protected by the credential above and by nothing else, exactly like the token endpoint
 * next to them.
 */
@Path("/api/clients")
@Produces(MediaType.APPLICATION_JSON)
public class IdpClientsController {

  /** What a caller asks for: which context this credential is being commissioned for. */
  public record CommissionRequest(String contextKind, String contextId) {}

  /**
   * The answer to a commission. <b>The secret is in this response and nowhere else</b> — the store
   * holds a hash — so a caller that loses it decommissions and commissions again.
   */
  public record CommissionResponse(
      String clientId,
      String secret,
      String owner,
      String contextKind,
      String contextId,
      String createdAt) {}

  /** One live commission, as the owner's reconcile reads it. No secret, ever. */
  public record CommissionView(
      String clientId, String owner, String contextKind, String contextId, String createdAt) {}

  @Inject ClientRegistry registry;

  @Inject DynamicClients dynamicClients;

  /**
   * Commission a credential for one context.
   *
   * <p>201 with the pair. The response carries <b>no {@code Location} header</b>: the URL a caller
   * reaches this service at is the deployment's — direct on the platform network for a service,
   * through the gateway for an operator — and this process knows neither, so a self-built absolute
   * URL would be wrong for somebody. The {@code clientId} in the body is the whole address.
   *
   * <p><b>The return type is {@code RestResponse<CommissionResponse>} and not a bare {@code
   * Response}, and that is not a style choice.</b> A {@code Response} carries its entity as an
   * {@code Object}, so the native build has no static type to register for reflection and the
   * packaged binary answers 500 with "no properties discovered" — green on the JVM, broken as
   * shipped. Measured here on 2026-08-14, caught by {@code IdpPackagedSurfaceIT}. Naming the type
   * keeps the status and the headers and tells the image builder what to keep.
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  public RestResponse<CommissionResponse> commission(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CommissionRequest request) {
    IdpClient caller = caller(authorization);
    if (!registry.isStatic(caller.clientId())) {
      throw OAuthException.accessDenied("a commissioned client may not commission another");
    }
    if (request == null) {
      throw OAuthException.invalidRequest(
          "a JSON body naming contextKind and contextId is required");
    }

    Commissioned issued =
        dynamicClients.commission(caller.clientId(), request.contextKind(), request.contextId());
    StoredClient client = issued.client();
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new CommissionResponse(
                client.clientId(),
                issued.secret(),
                client.owner(),
                client.contextKind(),
                client.contextId(),
                client.createdAt().toString()))
        // The body holds a credential. Same rule as the token response, same reason.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * The caller's own live commissions — for reconciliation: a service compares this against its
   * live contexts at boot and periodically, and decommissions whatever it no longer recognises.
   * Leaked credentials are answered structurally here rather than by a TTL.
   *
   * <p><b>Only the caller's own.</b> There is no listing across owners and no way to ask for
   * another's, because a service's live contexts are its own business.
   */
  @GET
  public List<CommissionView> list(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    IdpClient caller = caller(authorization);
    return dynamicClients.listOwnedBy(caller.clientId()).stream()
        .map(
            client ->
                new CommissionView(
                    client.clientId(),
                    client.owner(),
                    client.contextKind(),
                    client.contextId(),
                    client.createdAt().toString()))
        .toList();
  }

  /**
   * Decommission — the context ended.
   *
   * <p>204 and the row is gone, so the credential mints nothing from the next request onward.
   * <b>Tokens it already minted live out their {@code exp}</b>; that grace is the accepted cost
   * recorded on {@code qits.idp.token-ttl-seconds}, and it is why an owner decommissions at the end
   * of a context rather than treating this as an emergency stop.
   *
   * <p>The caller must be the owner, or the credential itself. Anything else is a 404 — the same
   * answer as an id that never existed, so nobody maps other services' contexts from here.
   */
  @DELETE
  @Path("/{clientId}")
  public Response decommission(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    IdpClient caller = caller(authorization);
    if (!dynamicClients.decommission(clientId, caller.clientId())) {
      throw OAuthException.notFound("no such commissioned client");
    }
    return Response.noContent().build();
  }

  /**
   * Who is calling. Basic only — this is a JSON API, not the token endpoint, so there is no form to
   * carry credentials and no second place to look.
   */
  private IdpClient caller(String authorization) {
    BasicCredentials credentials = BasicCredentials.parse(authorization);
    if (credentials == null) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return registry.authenticate(credentials.clientId(), credentials.secret());
  }
}
