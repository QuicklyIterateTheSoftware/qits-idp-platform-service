package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import eu.wohlben.qits.idp.persistence.IdpDynamicClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The commission API end to end: a service asks for a credential for a context, the credential
 * mints tokens exactly like the service client that asked, and deleting it stops that at once.
 *
 * <p>The owners are the suite's static clients from {@code src/test/resources/application.properties}
 * — {@code test-broad} (two audiences and a granted {@code project} claim) and {@code test-narrow}
 * (one audience). What a commissioned credential inherits is checked against the first of them, and
 * owner scoping against both.
 *
 * <p>Every test names its own {@code contextKind}, because the suite shares one application and
 * therefore one store: the listing case filters on it rather than assuming an empty table.
 */
@QuarkusTest
public class CommissionedClientsTest {

  private static final String OWNER = "test-broad";
  private static final String OWNER_SECRET = "test-broad-secret";
  private static final String OTHER_OWNER = "test-narrow";
  private static final String OTHER_OWNER_SECRET = "test-narrow-secret";

  @jakarta.inject.Inject IdpDynamicClientRepository repository;

  @Test
  public void aCommissionedClientMintsExactlyLikeTheServiceClientThatCommissionedIt()
      throws Exception {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "mint-kind", "run/4711");

    String token =
        token(pair.get("clientId"), pair.get("secret"), "&audience=qits-deployments")
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-deployments");
    assertEquals(pair.get("clientId"), claims.getSubject(), "the commissioned id is the sub");
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertNotNull(PublishedJwks.kidOf(token), "signed by the same key as everything else");

    // Full access for now: the owner's audiences and the owner's granted claims, verbatim.
    String all =
        token(pair.get("clientId"), pair.get("secret"), "").statusCode(200).extract()
            .path("access_token");
    JwtClaims allClaims = PublishedJwks.verify(all, "prod-qits-ci");
    assertEquals(
        List.of("prod-qits-ci", "qits-deployments"),
        PublishedJwks.audienceOf(allClaims),
        "a commissioned client asking for nothing gets its owner's whole list");
    assertEquals("qits", allClaims.getClaimValueAsString("project"), "the owner's granted claim");

    // And the owner's limits are its limits.
    token(pair.get("clientId"), pair.get("secret"), "&audience=qits-platform-artifacts")
        .statusCode(400)
        .body("error", equalTo("invalid_target"));
  }

  @Test
  public void theSecretIsReturnedOnceAndTheRowHoldsOnlyAHash() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "hash-kind", "ctx-1");

    IdpDynamicClient row =
        QuarkusTransaction.requiringNew().call(() -> repository.findById(pair.get("clientId")));
    assertNotNull(row, "the commission is a row");
    assertNotEquals(pair.get("secret"), row.secretHash, "the plaintext must not be stored");
    assertTrue(row.secretHash.startsWith("sha-256:"), "the scheme is named in the stored value");
    assertFalse(row.secretHash.contains(pair.get("secret")), "nor any part of it");
    assertEquals(OWNER, row.owner);
    assertEquals("hash-kind", row.contextKind);
    assertEquals("ctx-1", row.contextId);
    assertNotNull(row.createdAt);
  }

  @Test
  public void theClientIdIsReadableAndIsNoServiceClientsName() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "ci-run", "Project/Build #918");
    String clientId = pair.get("clientId");

    assertTrue(clientId.startsWith(DynamicClients.ID_PREFIX + "ci-run-"), clientId);
    assertTrue(
        clientId.contains("project-build-918"), "the context is legible in a listing: " + clientId);
    // The static ids are the names services are dialed by; none of them can be produced here.
    assertFalse(
        List.of("prod-qits-ci", "qits-platform-artifacts", "prod-qits-workspaces", "prod-qits-gateway")
            .contains(clientId));
    assertTrue(clientId.length() <= 128, "the column is varchar(128)");
  }

  @Test
  public void decommissioningStopsTheMintingImmediately() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "revoke-kind", "ctx-2");
    token(pair.get("clientId"), pair.get("secret"), "").statusCode(200);

    decommission(OWNER, OWNER_SECRET, pair.get("clientId")).statusCode(204);

    // The very next request, with no cache to wait out. Tokens already minted live out their exp;
    // that grace is the accepted cost and is not what this asserts.
    token(pair.get("clientId"), pair.get("secret"), "")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    long rows =
        QuarkusTransaction.requiringNew()
            .call(() -> repository.count("clientId = ?1", pair.get("clientId")));
    assertEquals(0L, rows, "decommissioning is deleting the row");
  }

  @Test
  public void onlyTheOwnerMayDecommission() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "owner-kind", "ctx-3");

    // Another service client is told what a caller naming a nonexistent id is told.
    decommission(OTHER_OWNER, OTHER_OWNER_SECRET, pair.get("clientId"))
        .statusCode(404)
        .body("error", equalTo("not_found"));
    token(pair.get("clientId"), pair.get("secret"), "").statusCode(200);

    decommission(OWNER, OWNER_SECRET, pair.get("clientId")).statusCode(204);
  }

  @Test
  public void aContextMayHandItsOwnCredentialBack() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "self-kind", "ctx-4");

    decommission(pair.get("clientId"), pair.get("secret"), pair.get("clientId")).statusCode(204);

    token(pair.get("clientId"), pair.get("secret"), "").statusCode(401);
  }

  @Test
  public void aCommissionedClientMayNotCommissionAnother() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "spread-kind", "ctx-5");

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(pair.get("clientId"), pair.get("secret")))
        .body("{\"contextKind\":\"spread-kind\",\"contextId\":\"ctx-5-child\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));

    // It authenticates fine — it is only this verb it may not use.
    given()
        .header("Authorization", basic(pair.get("clientId"), pair.get("secret")))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200);
  }

  @Test
  public void theListingShowsTheCallersOwnCommissionsAndNoOthers() {
    String kind = "listing-kind";
    Map<String, String> mine = commission(OWNER, OWNER_SECRET, kind, "ctx-mine");
    Map<String, String> alsoMine = commission(OWNER, OWNER_SECRET, kind, "ctx-mine-2");
    Map<String, String> theirs = commission(OTHER_OWNER, OTHER_OWNER_SECRET, kind, "ctx-theirs");

    List<String> ownersOwn = listedIds(OWNER, OWNER_SECRET, kind);
    assertTrue(ownersOwn.contains(mine.get("clientId")));
    assertTrue(ownersOwn.contains(alsoMine.get("clientId")));
    assertFalse(ownersOwn.contains(theirs.get("clientId")), "no cross-owner listing");

    List<String> othersOwn = listedIds(OTHER_OWNER, OTHER_OWNER_SECRET, kind);
    assertEquals(List.of(theirs.get("clientId")), othersOwn);

    // What a reconcile reads on each row.
    String row = "find { it.clientId == '" + theirs.get("clientId") + "' }.";
    given()
        .header("Authorization", basic(OTHER_OWNER, OTHER_OWNER_SECRET))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body(row + "owner", equalTo(OTHER_OWNER))
        .body(row + "contextKind", equalTo(kind))
        .body(row + "contextId", equalTo("ctx-theirs"))
        .body(row + "createdAt", org.hamcrest.Matchers.notNullValue());

    // A listing never carries a secret, in either spelling.
    String document =
        given()
            .header("Authorization", basic(OWNER, OWNER_SECRET))
            .when()
            .get("/idp/api/clients")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    assertFalse(document.contains(mine.get("secret")), "a listing must not carry a secret");
    assertFalse(document.contains("secretHash"), "nor the hash of one");
  }

  @Test
  public void aCommissionNeedsAContextItCanNameInAClientId() {
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci-run\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci-run\",\"contextId\":\"  \"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    // A kind goes into a client id, so it is a lowercase slug and nothing else.
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"CI Run\",\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci/../run\",\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void everyVerbNeedsTheCallersOwnCredentials() {
    // No header at all.
    given()
        .contentType(ContentType.JSON)
        .body("{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .header("WWW-Authenticate", "Basic realm=\"qits-platform-idp\"");
    given().when().get("/idp/api/clients").then().statusCode(401);
    given().when().delete("/idp/api/clients/dyn-anon-ctx-abc").then().statusCode(401);

    // The wrong secret.
    commissionRaw(OWNER, "wrong", "{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));

    // A SHIPPED service client with no secret configured stays unusable here too — the same
    // reading as at the token endpoint, so there is no door this API opens that that one does not.
    commissionRaw(
            "prod-qits-gateway", "", "{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void decommissioningSomethingThatIsNotThereIsNotAnError() {
    decommission(OWNER, OWNER_SECRET, "dyn-nothing-here-Aaaaaaaaaaaaaaaaaaaaaa")
        .statusCode(404)
        .body("error", equalTo("not_found"));
    // A static client id is not a commission and cannot be deleted through this door either.
    decommission(OWNER, OWNER_SECRET, "prod-qits-ci").statusCode(404);
  }

  // --- helpers ------------------------------------------------------------------------------

  private static Map<String, String> commission(
      String owner, String secret, String contextKind, String contextId) {
    return commissionRaw(
            owner,
            secret,
            "{\"contextKind\":\"" + contextKind + "\",\"contextId\":\"" + contextId + "\"}")
        .statusCode(201)
        .header("Cache-Control", "no-store")
        .body("owner", equalTo(owner))
        .body("contextKind", equalTo(contextKind))
        .body("contextId", equalTo(contextId))
        .extract()
        .as(new io.restassured.common.mapper.TypeRef<Map<String, String>>() {});
  }

  private static ValidatableResponse commissionRaw(String owner, String secret, String body) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(owner, secret))
        .body(body)
        .when()
        .post("/idp/api/clients")
        .then();
  }

  private static ValidatableResponse decommission(String caller, String secret, String clientId) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .delete("/idp/api/clients/" + clientId)
        .then();
  }

  private static List<String> listedIds(String caller, String secret, String contextKind) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .extract()
        .path("findAll { it.contextKind == '" + contextKind + "' }.clientId");
  }

  private static ValidatableResponse token(String clientId, String secret, String extraForm) {
    return given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic(clientId, secret))
        .body("grant_type=client_credentials" + extraForm)
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
