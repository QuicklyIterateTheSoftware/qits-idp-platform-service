package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

/**
 * The two documents a consumer reads before it can validate anything. Both are asserted at their
 * absolute paths: {@code /idp/.well-known/openid-configuration} is where an OIDC client derives the
 * discovery document from an auth-server-url of {@code .../idp}, and moving it silently breaks
 * every consumer at once.
 */
@QuarkusTest
public class IdpMetadataTest {

  @Test
  public void theDiscoveryDocumentAdvertisesEndpointsDerivedFromTheIssuer() {
    given()
        .when()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo(PublishedJwks.ISSUER))
        .body("token_endpoint", equalTo(PublishedJwks.ISSUER + "/token"))
        .body("jwks_uri", equalTo(PublishedJwks.ISSUER + "/jwks"))
        .body(
            "grant_types_supported",
            contains("client_credentials", "authorization_code", "refresh_token"))
        .body(
            "token_endpoint_auth_methods_supported",
            containsInAnyOrder("client_secret_basic", "client_secret_post", "none"))
        .body("id_token_signing_alg_values_supported", contains("RS256"))
        .body(
            "claims_supported",
            hasItems(
                "iss",
                "sub",
                "aud",
                "groups",
                "project",
                "workspace",
                "branch",
                "credential_type",
                "git_ref_pattern"))
        .body("authorization_endpoint", equalTo(PublishedJwks.ISSUER + "/authorize"))
        .body("userinfo_endpoint", nullValue());
  }

  @Test
  public void theJwksPublishesOnlyPublicKeyMaterial() {
    given()
        .when()
        .get("/idp/jwks")
        .then()
        .statusCode(200)
        .body("keys", hasSize(1))
        .body("keys[0].kty", equalTo("RSA"))
        .body("keys[0].use", equalTo("sig"))
        .body("keys[0].alg", equalTo("RS256"))
        .body("keys[0].kid", not(nullValue()))
        .body("keys[0].n", not(nullValue()))
        .body("keys[0].e", equalTo("AQAB"))
        // The private half has no JWK member here, and must never gain one.
        .body("keys[0].d", nullValue())
        .body("keys[0].p", nullValue())
        .body("keys[0].q", nullValue());
  }
}
