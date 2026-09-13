package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * {@code /idp/api/service-clients} end to end (service-client-identity-plan.md, contract C2): the
 * database half of the client registry, managed rather than configured.
 *
 * <p>{@code test-broad} is the calling admin throughout — a shipped-shape environment client that
 * already holds {@code qits:system}, the same fixture {@code CommissionedClientsTest} uses as an
 * owner. Every test names its own client id, because the suite shares one store.
 */
@QuarkusTest
public class IdpServiceClientsControllerTest {

  private static final String ADMIN = "test-broad";
  private static final String ADMIN_SECRET = "test-broad-secret";

  @Inject IdpServiceClientRepository repository;

  @Test
  public void createAnswersOnceAndTheRowHoldsOnlyAHash() {
    String id = "svc-create-once";
    var answer =
        create(id).statusCode(201).header("Cache-Control", "no-store").extract();
    String secret = answer.path("secret");
    assertEquals(id, answer.path("clientId"));
    assertEquals(ADMIN, answer.path("createdBy"));
    assertNotNull(answer.path("createdAt"));
    assertNotNull(secret);

    IdpServiceClient row = QuarkusTransaction.requiringNew().call(() -> repository.findById(id));
    assertNotNull(row, "the create is a row");
    assertNotEquals(secret, row.secretHash, "the plaintext must not be stored");
    assertTrue(row.secretHash.startsWith("sha-256:"), "the scheme is named in the stored value");
    assertFalse(row.secretHash.contains(secret), "nor any part of it");

    // And the secret actually authenticates.
    token(id, secret, "&audience=qits-deployments").statusCode(200);
  }

  @Test
  public void createTwiceIsAConflict() {
    String id = "svc-conflict";
    create(id).statusCode(201);

    create(id).statusCode(409).body("error", equalTo("conflict"));
  }

  @Test
  public void anEnvironmentOnlyIdMayStillBeCreated() {
    // test-dual is on qits.idp.clients with its own secret and no database row yet — the ordinary
    // shape of a cutover (C5): the deployer finds no row and asks for one.
    create("test-dual").statusCode(201);

    get("test-dual").statusCode(200).body("source", equalTo("both"));

    // Both secrets now authenticate the same id.
    token("test-dual", "test-dual-env-secret", "&audience=qits-deployments").statusCode(200);
  }

  @Test
  public void badIdsAreRefused() {
    for (String bad :
        List.of(
            "Upper-Case",
            "-leading-dash",
            "dyn-looks-commissioned",
            "qits-git-workstation",
            "qits-cli",
            "")) {
      createRaw("{\"clientId\":\"" + bad + "\"}")
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
    createRaw("{}").statusCode(400);
    createRaw(null).statusCode(400);
  }

  @Test
  public void rotateKeepsThePreviousSecretLiveAndAnswersOnce() {
    String id = "svc-rotate";
    String original = create(id).statusCode(201).extract().path("secret");

    var rotated =
        given()
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .when()
            .post("/idp/api/service-clients/" + id + "/secret")
            .then()
            .statusCode(200)
            .header("Cache-Control", "no-store")
            .body("clientId", equalTo(id))
            .extract();
    String rotatedSecret = rotated.path("secret");
    assertNotNull(rotated.path("rotatedAt"));
    assertNotEquals(original, rotatedSecret);

    // Both still work: the new one, and the old one within its grace window (D4).
    token(id, rotatedSecret, "&audience=qits-deployments").statusCode(200);
    token(id, original, "&audience=qits-deployments").statusCode(200);
  }

  @Test
  public void rotatingAnUnknownIdIs404() {
    given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .post("/idp/api/service-clients/svc-never-created/secret")
        .then()
        .statusCode(404)
        .body("error", equalTo("not_found"));
  }

  @Test
  public void getAndListReportTheSourceOfEachId() {
    String id = "svc-source";
    create(id).statusCode(201);

    get(id).statusCode(200).body("source", equalTo("database")).body("clientId", equalTo(id));
    // prod-qits-ci is shipped, environment-only, and never given a database row by this suite.
    get("prod-qits-ci").statusCode(200).body("source", equalTo("environment"));
    get("svc-does-not-exist").statusCode(404).body("error", equalTo("not_found"));

    String document =
        given()
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .when()
            .get("/idp/api/service-clients")
            .then()
            .statusCode(200)
            .body("find { it.clientId == '" + id + "' }.source", equalTo("database"))
            .extract()
            .asString();
    assertFalse(document.contains("secretHash"), "a listing must never carry a secret or its hash");
  }

  @Test
  public void deleteRemovesTheRowAnd404sTwice() {
    String id = "svc-delete";
    create(id).statusCode(201);

    delete(id).statusCode(204);
    delete(id).statusCode(404).body("error", equalTo("not_found"));
    get(id).statusCode(404);
  }

  @Test
  public void aServiceClientMayNotDeleteItsOwnRow() {
    String id = "svc-self-delete";
    String secret = create(id).statusCode(201).extract().path("secret");

    given()
        .header("Authorization", basic(id, secret))
        .when()
        .delete("/idp/api/service-clients/" + id)
        .then()
        .statusCode(409)
        .body("error", equalTo("conflict"));

    // It still exists, and it may delete something else.
    get(id).statusCode(200);
    String other = "svc-self-delete-other";
    create(other).statusCode(201);
    given()
        .header("Authorization", basic(id, secret))
        .when()
        .delete("/idp/api/service-clients/" + other)
        .then()
        .statusCode(204);
  }

  @Test
  public void aCommissionedCallerIsRefused() {
    // A commissioned credential of test-broad's, via the existing commission API.
    var pair =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .body("{\"contextKind\":\"svc-mgmt-refusal\",\"contextId\":\"ctx\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract();
    String clientId = pair.path("clientId");
    String secret = pair.path("secret");

    createRaw(clientId, secret, "{\"clientId\":\"svc-from-commission\"}")
        .statusCode(403)
        .body("error", equalTo("access_denied"));
    given()
        .header("Authorization", basic(clientId, secret))
        .when()
        .get("/idp/api/service-clients")
        .then()
        .statusCode(403);
  }

  @Test
  public void aServiceClientWithoutTheSystemRoleIsRefused() {
    createRaw("test-no-system", "test-no-system-secret", "{\"clientId\":\"svc-no-role\"}")
        .statusCode(403)
        .body("error", equalTo("access_denied"));
  }

  @Test
  public void everyVerbNeedsCredentials() {
    given().when().get("/idp/api/service-clients").then().statusCode(401);
    createRaw("wrong-caller", "wrong", "{\"clientId\":\"svc-anon\"}").statusCode(401);
  }

  @Test
  public void aDatabaseOnlyTokenCarriesTheCodeShapeExactly() throws Exception {
    String id = "svc-token-shape";
    String secret = create(id).statusCode(201).extract().path("secret");

    JwtClaims claims =
        PublishedJwks.verify(
            token(id, secret, "&audience=some-service").statusCode(200).extract().path("access_token"),
            "some-service");

    assertEquals(id, claims.getSubject());
    // A database service client's audience rule copies a requested one back unchecked, plus the
    // platform-wide one, always (service-client-identity-plan.md, C2).
    assertEquals(List.of("some-service", "qits-platform"), claims.getAudience());
    assertEquals(
        List.of("qits:system", "qits-platform:system", "clients/" + id),
        claims.getStringListClaimValue("groups"));
    assertEquals("*", claims.getClaimValueAsString("project"), "D3: every project, in code");
    assertFalse(claims.hasClaim("workspace"));
    assertFalse(claims.hasClaim("branch"));
  }

  // --- helpers --------------------------------------------------------------------------------

  private static ValidatableResponse create(String clientId) {
    return createRaw(ADMIN, ADMIN_SECRET, "{\"clientId\":\"" + clientId + "\"}");
  }

  private static ValidatableResponse createRaw(String body) {
    return createRaw(ADMIN, ADMIN_SECRET, body);
  }

  private static ValidatableResponse createRaw(String caller, String secret, String body) {
    var spec =
        given().contentType(ContentType.JSON).header("Authorization", basic(caller, secret));
    if (body != null) {
      spec = spec.body(body);
    }
    return spec.when().post("/idp/api/service-clients").then();
  }

  private static ValidatableResponse get(String clientId) {
    return given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .get("/idp/api/service-clients/" + clientId)
        .then();
  }

  private static ValidatableResponse delete(String clientId) {
    return given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .delete("/idp/api/service-clients/" + clientId)
        .then();
  }

  private static ValidatableResponse token(String clientId, String secret, String extraForm) {
    return given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + secret + extraForm)
        .when()
        .post("/idp/token")
        .then();
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
