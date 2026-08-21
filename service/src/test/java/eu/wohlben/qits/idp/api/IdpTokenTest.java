package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Test;

/**
 * The token endpoint end to end. Tests address the absolute {@code /idp/token} path, which is what
 * makes them catch a prefix regression, and every issued token is verified against what {@code
 * /idp/jwks} published rather than against anything reachable in-process.
 *
 * <p>The clients come from {@code src/test/resources/application.properties}. {@code
 * prod-qits-gateway} is one of the SHIPPED service clients, secret-less exactly as it ships — that
 * is what the blank-secret case runs against.
 */
@QuarkusTest
public class IdpTokenTest {

  @Test
  public void aClientGetsAVerifiableTokenForTheAudienceItAsksFor() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret"
                + "&audience=qits-deployments")
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            // The SHIPPED lifetime, raised to an hour on 2026-08-14 with the commission model.
            // That the key is honoured at all is TokenLifetimeTest's; this pins the default.
            .body("expires_in", equalTo(3600))
            .body("access_token", notNullValue())
            // RFC 6749 §5.1 — a token response is never cached.
            .header("Cache-Control", "no-store")
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-deployments");
    assertEquals("test-broad", claims.getSubject());
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertEquals(List.of("qits-deployments"), PublishedJwks.audienceOf(claims));
    // The configured roles, then the self-role this service stamps. The whole claim is pinned
    // rather than searched: `groups` is the token's shape, and a change to it is a change every
    // consumer reads.
    assertEquals(
        List.of("qits:system", "qits-platform:system", "clients/test-broad"),
        claims.getStringListClaimValue("groups"));
    assertNotNull(claims.getIssuedAt(), "iat");
    assertEquals(
        3600,
        claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue(),
        "exp must be iat plus the configured lifetime");
    assertNotNull(
        PublishedJwks.kidOf(token), "every token carries a kid, or rotation is a flag day");
  }

  @Test
  public void basicAuthenticationWorksLikeTheFormFields() throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .header("Authorization", basic("test-broad", "test-broad-secret"))
            .body("grant_type=client_credentials&audience=prod-qits-ci")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");

    assertEquals("test-broad", PublishedJwks.verify(token, "prod-qits-ci").getSubject());
  }

  @Test
  public void aRequestNamingNoAudienceGetsEveryAudienceTheClientMayHave() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-deployments");
    assertEquals(
        List.of("prod-qits-ci", "qits-deployments"), PublishedJwks.audienceOf(claims));
  }

  @Test
  public void grantedClaimsRideAlongAndUngrantedOnesDoNot() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret"
                + "&audience=qits-deployments")
            .statusCode(200)
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-deployments");
    assertEquals("qits", claims.getClaimValueAsString("project"), "the granted claim, verbatim");
    assertFalse(claims.hasClaim("workspace"), "an ungranted claim must not appear");
    assertFalse(claims.hasClaim("branch"), "an ungranted claim must not appear");
    assertNull(claims.getClaimValue("scope"), "claims, not scope strings");
  }

  @Test
  public void everyClientTokenNamesItsOwnClientAndNoOther() throws Exception {
    String broad =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret"
                + "&audience=qits-deployments")
            .statusCode(200)
            .extract()
            .path("access_token");
    String narrow =
        post("grant_type=client_credentials"
                + "&client_id=test-narrow"
                + "&client_secret=test-narrow-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    List<String> broadGroups =
        PublishedJwks.verify(broad, "qits-deployments").getStringListClaimValue("groups");
    List<String> narrowGroups =
        PublishedJwks.verify(narrow, "qits-deployments").getStringListClaimValue("groups");

    assertTrue(broadGroups.contains("clients/test-broad"), "a client token names its own client");
    assertTrue(narrowGroups.contains("clients/test-narrow"), "a client token names its own client");
    // The point of the whole feature: a role naming one client is held by that client only, so
    // @RolesAllowed("clients/<x>") is a door exactly one caller can reach.
    assertFalse(
        narrowGroups.contains("clients/test-broad"),
        "no client may hold another client's self-role");
    assertFalse(
        broadGroups.contains("clients/test-narrow"),
        "no client may hold another client's self-role");
  }

  @Test
  public void aConfiguredRoleUnderTheReservedNamespaceIsRefused() {
    // test-role-thief configures clients/test-broad — the impersonation. Refused at the config
    // read, so the client mints nothing at all rather than minting an identity it was granted.
    post("grant_type=client_credentials"
            + "&client_id=test-role-thief"
            + "&client_secret=test-role-thief-secret")
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("error_description", containsString("clients/"));

    // And its own is refused too: it would be redundant, and allowing it would make writing the
    // prefix by hand look like something a deployment does.
    post("grant_type=client_credentials"
            + "&client_id=test-role-selfish"
            + "&client_secret=test-role-selfish-secret")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void aClientWithAReservedRoleIsRefusedAtTheOtherMachineSurfacesToo() {
    // Same config, every surface: the commission API authenticates through the same client lookup,
    // so a `clients/…` line makes the client unusable there as well rather than only at /token.
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic("test-role-thief", "test-role-thief-secret"))
        .body("{\"contextKind\":\"reserved-role\",\"contextId\":\"never\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void theWrongSecretIsRefused() {
    post("grant_type=client_credentials&client_id=test-broad&client_secret=wrong")
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .header("WWW-Authenticate", "Basic realm=\"qits-platform-idp\"");
  }

  @Test
  public void anUnknownClientIsRefused() {
    post("grant_type=client_credentials&client_id=not-a-client&client_secret=anything")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void aClientWithNoSecretIsUnusableRatherThanOpen() {
    // prod-qits-gateway is a SHIPPED service client with no secret configured — the state every
    // service client ships in. A blank secret must be refused like a wrong one, never accepted as
    // "no authentication required".
    post("grant_type=client_credentials&client_id=prod-qits-gateway&client_secret=")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    post("grant_type=client_credentials&client_id=prod-qits-gateway")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic("prod-qits-gateway", ""))
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void anAudienceTheClientMayNotHaveIsRefused() {
    post("grant_type=client_credentials"
            + "&client_id=test-narrow"
            + "&client_secret=test-narrow-secret"
            + "&audience=qits-platform-artifacts")
        .statusCode(400)
        .body("error", equalTo("invalid_target"));
  }

  @Test
  public void aClientWithNoAudiencesIsIssuedNothing() {
    post("grant_type=client_credentials"
            + "&client_id=test-audienceless"
            + "&client_secret=test-audienceless-secret")
        .statusCode(400)
        .body("error", equalTo("invalid_target"));
  }

  @Test
  public void onlyClientCredentialsIsSupported() {
    post("grant_type=password&client_id=test-broad&client_secret=test-broad-secret&username=a")
        .statusCode(400)
        .body("error", equalTo("unsupported_grant_type"));
    post("client_id=test-broad&client_secret=test-broad-secret")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void credentialsMayBePresentedOnlyOnce() {
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic("test-broad", "test-broad-secret"))
        .body("grant_type=client_credentials&client_id=test-broad&client_secret=test-broad-secret")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void aRequestWithNoCredentialsIsRefused() {
    post("grant_type=client_credentials").statusCode(401).body("error", equalTo("invalid_client"));
  }

  @Test
  public void aTokenForOneAudienceDoesNotVerifyForAnother() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-narrow"
                + "&client_secret=test-narrow-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    assertTrue(PublishedJwks.verify(token, "qits-deployments").hasClaim("aud"));
    assertThrows(
        InvalidJwtException.class,
        () -> PublishedJwks.verify(token, "qits-platform-artifacts"),
        "aud is what makes a token unusable at a service it was not minted for");
  }

  private static ValidatableResponse post(String form) {
    return given().contentType(ContentType.URLENC).body(form).when().post("/idp/token").then();
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
