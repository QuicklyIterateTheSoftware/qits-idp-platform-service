package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.control.IdpClients;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.ServiceClients.Issued;
import eu.wohlben.qits.idp.control.ServiceClients.StoredServiceClient;
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
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The service-client management API: {@code /idp/api/service-clients}, where a service client's
 * id and secret move from configuration into the database (service-client-identity-plan.md,
 * contract C2).
 *
 * <p><b>Auth is the same Basic pair every machine surface here uses</b> ({@link BasicCaller}), and
 * the caller must be a service client itself — environment or database, never commissioned — and
 * hold {@code qits:system}. There is no exception for a read: unlike the commission API next door,
 * nothing here accepts {@link BasicCaller#AGENT}, because migrating an id's secret is not a thing
 * an agent's context has any business doing.
 *
 * <p><b>An id that exists only in the environment registry may still be created here</b> (201): that
 * is the ordinary shape of a cutover (C5) — the deployer finds no database row, so it asks for one,
 * and the environment secret keeps authenticating the predecessor container through the start-first
 * overlap while the database secret authenticates the successor.
 */
@Path("/api/service-clients")
@Produces(MediaType.APPLICATION_JSON)
public class IdpServiceClientsController {

  /** The body of {@code POST /api/service-clients}. */
  public record CreateRequest(String clientId) {}

  /** {@code POST}'s answer: the pair, in this response and nowhere else. */
  public record CreatedResponse(String clientId, String secret, String createdBy, String createdAt) {}

  /** {@code POST …/secret}'s answer: the new pair. The old hash stays live for the grace window. */
  public record RotatedResponse(String clientId, String secret, String rotatedAt) {}

  /** {@code GET}'s answer, singular or in a list. Never a secret. */
  public record ServiceClientView(String clientId, String source, String createdAt, String rotatedAt) {}

  @Inject BasicCaller caller;

  @Inject ServiceClients serviceClients;

  @Inject IdpClients environmentClients;

  /**
   * Create a database row for this id.
   *
   * <p>{@code RestResponse<CreatedResponse>}, not a bare {@code Response}: a native image has no
   * type to register for a plain {@code Response}'s entity, and the packaged binary answers 500
   * where the JVM suite stayed green — the same rule {@code IdpClientsController} already pays for.
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  public RestResponse<CreatedResponse> create(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CreateRequest request) {
    IdpClient caller_ = requireSystemCaller(authorization);
    if (request == null || request.clientId() == null) {
      throw OAuthException.invalidRequest("a JSON body naming clientId is required");
    }
    String clientId = request.clientId().trim();
    serviceClients.requireValidId(clientId);
    if (serviceClients.find(clientId).isPresent()) {
      throw OAuthException.conflict(
          "a database row for this client id already exists; rotate its secret instead of"
              + " creating it again");
    }
    Issued issued = serviceClients.create(clientId, caller_.clientId());
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new CreatedResponse(
                issued.client().clientId(),
                issued.secret(),
                issued.client().createdBy(),
                issued.client().createdAt().toString()))
        // The body holds a credential. Same rule as the token response, same reason.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * Rotate the secret. The old hash becomes the previous one, valid for the grace window (D4); the
   * new secret is in this response and nowhere else.
   */
  @POST
  @Path("/{clientId}/secret")
  public RestResponse<RotatedResponse> rotate(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    requireSystemCaller(authorization);
    Issued issued =
        serviceClients
            .rotate(clientId)
            .orElseThrow(() -> OAuthException.notFound("no such service client"));
    return RestResponse.ResponseBuilder.create(
            Response.Status.OK,
            new RotatedResponse(
                issued.client().clientId(), issued.secret(), issued.client().rotatedAt().toString()))
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /** One id, from either or both registries — {@code source} says which. Never a secret. */
  @GET
  @Path("/{clientId}")
  public ServiceClientView get(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    requireSystemCaller(authorization);
    boolean inEnvironment = environmentClients.ids().contains(clientId);
    Optional<StoredServiceClient> db = serviceClients.find(clientId);
    if (!inEnvironment && db.isEmpty()) {
      throw OAuthException.notFound("no such service client");
    }
    return view(clientId, inEnvironment, db);
  }

  /** Every id either registry knows — migration progress, one row per id. */
  @GET
  public java.util.List<ServiceClientView> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    requireSystemCaller(authorization);
    Set<String> ids = new LinkedHashSet<>(environmentClients.ids());
    serviceClients.list().forEach(row -> ids.add(row.clientId()));
    return ids.stream()
        .map(
            id ->
                view(id, environmentClients.ids().contains(id), serviceClients.find(id)))
        .toList();
  }

  /**
   * Delete the database row. 404 when there is none; <b>409 when the caller deletes its own row</b>
   * — a service client must not be able to lock itself out of its own management surface.
   */
  @DELETE
  @Path("/{clientId}")
  public Response delete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    IdpClient caller_ = requireSystemCaller(authorization);
    if (caller_.clientId().equals(clientId)) {
      throw OAuthException.conflict("a service client may not delete its own row");
    }
    if (!serviceClients.delete(clientId)) {
      throw OAuthException.notFound("no such service client");
    }
    return Response.noContent().build();
  }

  /**
   * Basic, a service client (environment or database, never commissioned), holding {@code
   * qits:system} — every verb here, uniformly, because there is no read among them an agent or a
   * commissioned context has reason to make.
   */
  private IdpClient requireSystemCaller(String authorization) {
    return caller.staticOnly(
        authorization,
        "a commissioned client may not manage service clients",
        BasicCaller.PLATFORM_SYSTEM);
  }

  private static ServiceClientView view(
      String clientId, boolean inEnvironment, Optional<StoredServiceClient> db) {
    String source = inEnvironment && db.isPresent() ? "both" : inEnvironment ? "environment" : "database";
    return new ServiceClientView(
        clientId,
        source,
        db.map(row -> row.createdAt().toString()).orElse(null),
        db.map(StoredServiceClient::rotatedAt).map(Object::toString).orElse(null));
  }
}
