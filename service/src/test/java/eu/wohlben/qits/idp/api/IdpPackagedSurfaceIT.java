package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.wohlben.qits.idp.testdb.EmbeddedPg;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The whole service as it is <b>packaged</b> — the fast-jar under {@code mvn verify
 * -DskipITs=false}, the GraalVM binary under {@code mvn verify -Dnative}. The assertions are chosen
 * for what a native build can silently lose rather than for API coverage (that is the
 * {@code @QuarkusTest} suite's job):
 *
 * <ul>
 *   <li>the routes are where the config says — {@code quarkus.rest.path} and {@code
 *       quarkus.http.non-application-root-path} are build-time settings baked into the artifact,
 *       and an OIDC consumer derives the discovery URL from the first of them;
 *   <li>the shipped datasource <b>expression</b> resolves and connects, and {@code
 *       db/idp/migration/} survived as a resource — migrations are loaded by scanning a classpath
 *       location, exactly the shape native-image drops;
 *   <li><b>RSA key generation works in the packaged process.</b> Key generation, PKCS#8 encoding
 *       and RS256 signing all go through JCA providers, which is the other thing a native image
 *       can lose. A service that boots and then cannot mint is the failure this catches.
 * </ul>
 */
@QuarkusIntegrationTest
@TestProfile(IdpPackagedSurfaceIT.PackagedUnderTarget.class)
public class IdpPackagedSurfaceIT {

  private static final String SECRET = "packaged-it-secret";

  /**
   * Hands the launched artifact a database the way a deployment does — as the generic resource
   * triple, not as the datasource keys. The idp jar ships {@code jdbc.url=${QITS_RESOURCE_DB_URL}}
   * and its two siblings, so supplying the variables leaves the <b>shipped</b> expression itself
   * under test (the AUTO_SERVER lesson, applied to what replaced that URL). Expression expansion
   * reads the whole config, and these overrides reach the launched process as system properties, so
   * the same three names resolve.
   *
   * <p>The database is an embedded postgres this JVM starts. <b>Its url travels through a system
   * property rather than a static field</b>: a test profile is instantiated in more than one
   * classloader, so a field written by one copy is not the field the other reads, while the process
   * has exactly one property table.
   *
   * <p>The secret is an override for the same reason the shipped config has none: a client with no
   * secret is unusable, so the packaged process can only be asked to mint once a deployment (here,
   * this profile) gives it one.
   */
  public static class PackagedUnderTarget implements QuarkusTestProfile {

    /** Where the url is parked for whichever copy of this class is asked second. */
    private static final String URL_PROPERTY = "qits.test.packaged-it.db-url";

    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "QITS_RESOURCE_DB_URL", databaseUrl(),
          "QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER,
          "QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD,
          "qits.idp.client.prod-qits-workspaces.secret", SECRET);
    }

    private static synchronized String databaseUrl() {
      String recorded = System.getProperty(URL_PROPERTY);
      if (recorded != null) {
        return recorded;
      }
      // localhost resolves for the launched process too — it is a child of this JVM on this host.
      String url = EmbeddedPg.url("idp_packaged_it");
      System.setProperty(URL_PROPERTY, url);
      return url;
    }
  }

  @Test
  public void theDiscoveryDocumentIsWhereAnOidcConsumerLooksForIt() {
    // auth-server-url http://qits-platform-idp:8080/idp + OIDC's own derivation = this path. It
    // is a build-time route prefix, so the artifact is the only place it can be proven.
    given()
        .when()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo("http://qits-platform-idp:8080/idp"))
        .body("jwks_uri", equalTo("http://qits-platform-idp:8080/idp/jwks"));

    // prod-qits-gateway routes verbatim by prefix, so there is no unprefixed form to fall back to.
    given().when().get("/.well-known/openid-configuration").then().statusCode(404);
  }

  @Test
  public void theReadinessEndpointIsWhereTheDeploymentLooksForIt() {
    given()
        .when()
        .get("/idp/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"));
  }

  @Test
  public void thePackagedProcessGeneratesAKeyIntoTheShippedDatabaseAndSignsWithIt()
      throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id=prod-qits-workspaces&client_secret="
                    + SECRET
                    + "&audience=qits-platform-artifacts")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");

    assertNotNull(PublishedJwks.kidOf(token), "the kid header must survive the packaging");
    assertEquals(
        "prod-qits-workspaces",
        PublishedJwks.verify(token, "qits-platform-artifacts").getSubject());

    // That the round trip happened at all is the proof the shipped expression resolved: the jar
    // carries no fallback URL, so a process that reached a store did so through
    // QITS_RESOURCE_DB_URL, and one that had not would have died at Flyway before serving a route.
  }

  @Test
  public void anUnconfiguredClientStillCannotAuthenticate() {
    // Only prod-qits-workspaces was given a secret above. The other three ship without one and
    // must stay unusable in the packaged artifact too.
    given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=prod-qits-ci&client_secret=" + SECRET)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }
}
