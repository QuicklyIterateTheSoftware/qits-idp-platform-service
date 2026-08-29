package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.testdb.EmbeddedPg;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;

/**
 * The whole service as it is <b>packaged</b>, telling the platform's auth bootstrap <b>from the
 * minting end</b>.
 *
 * <p>Category {@code authentication}, and the name is exact rather than approximate: every sibling
 * service on the platform carries a {@code TokenValidationBootstrapIT} that proves the
 * <em>validating</em> end of one story — a service fetches this service's JWKS at startup, and a
 * bearer signed by the key it found opens its guarded surface. Those stories all stand on a {@code
 * MockIdp}, because a service under test cannot also be the issuer. <b>This is the same story with
 * the mock taken out.</b> qits-platform-idp validates nothing against an OIDC tenant — it has none,
 * and there is no {@code MockIdp} here for exactly that reason. It MINTS, so what is asserted is
 * the half every sibling has to stand in for: the credential goes in, the bearer comes out, and the
 * public key that validates it is on the document the sibling fetches.
 *
 * <p><b>There is no far side at all, and that is the shape of this service rather than an
 * omission.</b> The idp is a leaf: it dials the postgres its datasource names and nothing else, so
 * there is no upstream to record and no stand-in to start. The recorded interactions are therefore
 * all between a platform service and this one — which is precisely the sequence diagram a reader of
 * the sibling stories arrives here looking for.
 *
 * <p>Why the PACKAGED artifact and not a {@code @QuarkusTest}: the suite's clients come from {@code
 * src/test/resources/application.properties}, which is not in the jar. The launched process reads
 * the <b>shipped</b> registry — the {@code qits.idp.clients} list, the audience lists and the roles
 * lines in the {@code idp} jar's {@code META-INF/microprofile-config.properties} — so what the
 * assertions below pin is the deployment's own configuration, secret excepted, and not a fixture
 * that resembles it. The signing key is generated into the shipped datasource expression on the way
 * up, which {@link IdpPackagedSurfaceIT} already proves survives packaging; here it is the story's
 * subject rather than its precondition.
 *
 * <p>It is also this repo's first <b>userflow</b>: the proof doubles as documentation,
 * emitted under {@code target/userstories/} with the interactions drawn as a sequence diagram.
 * Both stories are browserless (an {@code Interactions} parameter and no {@code Flow}), so the
 * framework's transitive Playwright never launches anything — which is what lets this run in a
 * step container with no browser in it.
 *
 * <p><b>This IT is named on the command line rather than opted in from the pom</b> ({@code
 * .config/qits/ci-event-userflows.yml}): {@link IdpPackagedSurfaceIT} is the module's other IT and
 * half of it is about the CLIENT — the {@code <base href>}, the deep links, the fallback that must
 * not swallow a machine path — which the userflow run deliberately does not build ({@code
 * -Dquarkus.quinoa=false}, and the webui submodule arrives empty in a step container). A blanket
 * {@code -DskipITs=false} would make that quinoa-less run red on a test that is right, so {@code
 * skipITs} stays true in the root pom and keeps meaning "run everything" for the {@code native}
 * profile that sets it.
 */
@QuarkusIntegrationTest
@TestProfile(TokenIssuanceBootstrapIT.PackagedAsTheIssuer.class)
public class TokenIssuanceBootstrapIT {

  static final String CATEGORY = "authentication";
  static final String MINTED_SLUG =
      "a-platform-service-exchanges-its-client-credentials-for-a-bearer";
  static final String REFUSED_SLUG = "the-wrong-secret-mints-nothing-and-the-jwks-stays-open";

  /**
   * The client this story is told as. It is a SHIPPED static client — one of the three names in the
   * jar's {@code qits.idp.clients} — so its audiences, its roles and its refusals below are the
   * deployment's own configuration. Only the secret is supplied, because a static client ships
   * without one on purpose and is unusable until a deployment gives it one.
   */
  static final String CLIENT = "prod-qits-ci";

  /** What a deployment sets as {@code QITS_IDP_CLIENT_PROD_QITS_CI_SECRET}. */
  static final String SECRET = "userflow-it-secret";

  /**
   * The audience the story asks for: the deployer's intake, which is the platform's first real
   * service-to-service call and an entry on this client's shipped audience list. Note it carries no
   * environment prefix — qits-deployments is a platform service and receives tokens without minting
   * any, so it is an audience with no client.
   */
  static final String AUDIENCE = "qits-deployments";

  /**
   * An audience nobody's shipped list carries. Asking for it is the {@code invalid_target} case,
   * and it is deliberately a plausible service name rather than nonsense: the refusal that matters
   * is the one a real adoption walks into.
   */
  static final String UNENTITLED_AUDIENCE = "prod-qits-observability";

  /**
   * Hands the launched artifact its config the way a deployment does — the generic resource triple
   * and one client secret, and nothing else, because that is the whole of what an idp deployment
   * supplies ({@code .config/qits/deployments.yml} declares {@code resources: postgresql:db} and
   * the deployer injects the three names the shipped datasource expression reads). Every key here
   * is a RUNTIME key: a packaged process takes its configuration as {@code -D} arguments on a jar
   * that was already built, so a build-time key would be silently ignored and this would prove
   * something other than what it says.
   *
   * <p>The database is the same embedded postgres the surefire suite spawns, under a name of this
   * IT's own — {@code idp_userflows_it}, beside {@link IdpPackagedSurfaceIT}'s {@code
   * idp_packaged_it} — so the two launched processes can never mean the same schema, and each
   * generates its own signing key. <b>Its url travels through a system property rather than a
   * static field</b>: a test profile is instantiated in more than one classloader, so a field
   * written by one copy is not the field the other reads, while the process has exactly one
   * property table.
   */
  public static class PackagedAsTheIssuer implements QuarkusTestProfile {

    /** Where the url is parked for whichever copy of this class is asked second. */
    private static final String URL_PROPERTY = "qits.test.userflow-it.db-url";

    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "QITS_RESOURCE_DB_URL", databaseUrl(),
          "QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER,
          "QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD,
          "qits.idp.client." + CLIENT + ".secret", SECRET,
          // Dark outside a deployment, like %dev/%test — and it is the ONE dial-out this process
          // has besides its own datasource, so disabling it leaves the launched artifact reaching
          // for nothing this step container cannot answer.
          "quarkus.otel.sdk.disabled", "true");
    }

    private static synchronized String databaseUrl() {
      String recorded = System.getProperty(URL_PROPERTY);
      if (recorded != null) {
        return recorded;
      }
      // localhost resolves for the launched process too — it is a child of this JVM on this host.
      String url = EmbeddedPg.url("idp_userflows_it");
      System.setProperty(URL_PROPERTY, url);
      return url;
    }
  }

  @UserStory(
      value = "A platform service exchanges its client credentials for a bearer",
      category = "authentication")
  @UserStoryDescription(
      """
      This is the other half of the story every qits service tells. A sibling boots, fetches the
      platform's signing keys from qits-platform-idp and accepts a bearer that carries them —
      and to prove it, stands a mock idp where this service really is. Here there is no mock:
      the issuer itself is running, packaged exactly as it deploys.

      A platform service reaches it the way OIDC says to. It knows one string — the issuer,
      `http://qits-platform-idp:8080/idp` — derives the discovery document from it, and follows
      the document to the token endpoint and to the JWKS. Then it presents the credential pair
      its deployment gave it and asks for the one audience it means to call.

      What comes back is a bearer that says who the caller is (`sub`), what it may be presented
      to (`aud`) and what it is (`groups` — the configured system roles plus `clients/<its own
      id>`, which the idp stamps and nobody can be granted). And the key that signed it is on the
      published JWKS, under the `kid` the token names: the token and the document a consumer
      fetches are the two ends of one key, which is the whole of why offline validation works.
      """)
  void aPlatformServiceMintsABearerAndTheKeyThatSignedItIsPublished(Interactions story)
      throws Exception {
    story.note(
        "qits-platform-idp starts against its own database and generates the signing key into it");
    given().get("/idp/q/health/ready").then().statusCode(200).body("status", equalTo("UP"));

    // The consumer's first move, and the only address it was configured with. Everything below is
    // reached by following this document rather than by knowing a path — which is what makes the
    // issuer string the single seam between this service and every consumer of it.
    given()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo(PublishedJwks.ISSUER))
        .body("token_endpoint", equalTo(PublishedJwks.ISSUER + "/token"))
        .body("jwks_uri", equalTo(PublishedJwks.ISSUER + "/jwks"))
        .body("grant_types_supported", hasItem("client_credentials"))
        .body("id_token_signing_alg_values_supported", hasItem("RS256"));
    story
        .happened(CLIENT, "qits-platform-idp", "GET /idp/.well-known/openid-configuration")
        .as("discovery-read");

    // The exchange itself: client_secret_post, RFC 6749 client_credentials, one named audience.
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id="
                    + CLIENT
                    + "&client_secret="
                    + SECRET
                    + "&audience="
                    + AUDIENCE)
            .post("/idp/token")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            // The SHIPPED lifetime — an hour since the commission model landed, and this process
            // reads the jar's own default rather than a test file's.
            .body("expires_in", equalTo(3600))
            // RFC 6749 §5.1: a token response is never cached, anywhere.
            .header("Cache-Control", "no-store")
            .extract()
            .path("access_token");
    story
        .happened(
            CLIENT,
            "qits-platform-idp",
            "POST /idp/token (client_credentials, audience=" + AUDIENCE + ")")
        .as("bearer-minted");

    // End (a), the token's: verified the way a consumer would — against whatever /idp/jwks
    // publishes, over HTTP, resolving the key by the token's own kid. Verifying against a key this
    // JVM could reach in-process would pass even if the published document were empty.
    JwtClaims claims = PublishedJwks.verify(token, AUDIENCE);
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer(), "iss is the configured issuer");
    assertEquals(CLIENT, claims.getSubject(), "sub is the client that authenticated");
    assertEquals(
        List.of(AUDIENCE),
        PublishedJwks.audienceOf(claims),
        "aud is exactly the audience that was asked for, never the whole allowed list");
    // The claim pinned whole rather than searched: `groups` is the token's shape, and a change to
    // it is a change every consumer reads. The two system roles are this client's SHIPPED lines;
    // the third is the self-role the idp mints from the id that authenticated and grants nowhere,
    // which is what lets a resource service write @RolesAllowed("clients/prod-qits-ci") and know
    // exactly one caller can reach the door.
    assertEquals(
        List.of("qits:system", "qits-platform:system", "clients/" + CLIENT),
        claims.getStringListClaimValue("groups"),
        "the configured roles, then the self-role this service stamps");
    story
        .happened(
            "qits-platform-idp",
            CLIENT,
            "200 Bearer (sub="
                + CLIENT
                + ", aud="
                + AUDIENCE
                + ", groups=[…, clients/"
                + CLIENT
                + "])")
        .as("bearer-answered");

    // End (b), the document's: the key a sibling fetches at startup is the key that signed this
    // token — spelled out with plain JCA rather than left to the resolver above, because "the
    // published key validates the signature" is the sentence the whole platform's offline
    // validation rests on, and it is worth reading as an assertion rather than as a side effect.
    String kid = PublishedJwks.kidOf(token);
    assertNotNull(kid, "every token carries a kid, or rotation is a flag day");
    thePublishedKeyValidatesTheSignature(token, kid);
    story
        .happened(CLIENT, "qits-platform-idp", "GET /idp/jwks (the key with kid=" + kid + ")")
        .as("signing-key-published");
  }

  @UserStory(
      value = "The wrong secret mints nothing, and the JWKS stays open",
      category = "authentication")
  @UserStoryDescription(
      """
      The flip side of being the platform's issuer: what must be refused, and the one thing that
      must never be.

      A wrong secret is `invalid_client`, and the refusal is deliberately coarse — which of
      "unknown client", "no secret configured" and "wrong secret" happened is not something the
      caller is told, because the caller is not always the one who should learn it. An audience
      the client is not entitled to is `invalid_target`, and it is the interesting one: that
      request AUTHENTICATED. A leaked or misconfigured credential is bounded by the audience list
      its deployment gave it, so authentication succeeding and authorization failing must be two
      different answers with two different codes.

      And the JWKS stays served to anyone who asks, with no credential of any kind. It has to:
      every service on the platform fetches it at boot, BEFORE it holds a token, and a JWKS
      behind a bearer would be a service unable to validate the bearer that would let it fetch
      the JWKS. The discovery document is open for the same reason. Nothing secret is on either
      — the published key is the public half and carries no private member, and never gains one.
      """)
  void aWrongSecretAndAnUnentitledAudienceAreDifferentRefusals(Interactions story) {
    // (a) authentication fails. The client id is real and on the shipped list; the secret is not.
    given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id="
                + CLIENT
                + "&client_secret=not-the-secret&audience="
                + AUDIENCE)
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .body("access_token", nullValue());
    story
        .happened("an impostor", "qits-platform-idp", "POST /idp/token (wrong secret) -> 401")
        .as("wrong-secret-refused");

    // (b) authentication SUCCEEDS and authorization fails. Same credential as the story above,
    // asking for an audience that is on nobody's shipped list — 400 invalid_target, RFC 8707's
    // code, and a different answer from (a) on purpose.
    given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id="
                + CLIENT
                + "&client_secret="
                + SECRET
                + "&audience="
                + UNENTITLED_AUDIENCE)
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_target"))
        .body("access_token", nullValue());
    story
        .happened(
            CLIENT,
            "qits-platform-idp",
            "POST /idp/token (audience=" + UNENTITLED_AUDIENCE + ") -> 400 invalid_target")
        .as("unentitled-audience-refused");

    // (c) the two bootstrap doors, with no credential presented at all. This service configures no
    // HTTP path permissions — its guarded surfaces check the caller in code — so today this passes
    // by construction; it is asserted at the DEPLOYED posture so that a future blanket policy over
    // /idp/* fails here rather than in every consumer's startup at once.
    given()
        .get("/idp/jwks")
        .then()
        .statusCode(200)
        .body("keys[0].kty", equalTo("RSA"))
        .body("keys[0].use", equalTo("sig"))
        .body("keys[0].alg", equalTo("RS256"))
        // The private half has no JWK member here, and must never gain one.
        .body("keys[0].d", nullValue())
        .body("keys[0].p", nullValue())
        .body("keys[0].q", nullValue());
    given().get("/idp/.well-known/openid-configuration").then().statusCode(200);
    story
        .happened(
            "any service, holding nothing",
            "qits-platform-idp",
            "GET /idp/jwks and /idp/.well-known/openid-configuration (no credential) -> 200")
        .as("bootstrap-doors-open");
  }

  /**
   * The published key, rebuilt from its JWK members and used to verify the token's own signature —
   * plain JCA, no JOSE library in between.
   *
   * <p>{@code n} and {@code e} are base64url of the UNSIGNED big-endian value, so they are read
   * back through {@link BigInteger#BigInteger(int, byte[])} with a positive signum: the
   * two-argument constructor keeps a modulus whose top bit is set from reading as negative,
   * which is the same rounding the service applies when it writes them.
   *
   * <p>The signing input of a JWS is the compact serialization up to (and excluding) the last dot,
   * ASCII bytes as they appear on the wire.
   */
  private static void thePublishedKeyValidatesTheSignature(String jwt, String kid)
      throws Exception {
    JsonPath jwks = JsonPath.from(PublishedJwks.document());
    Map<String, Object> jwk = jwks.getMap("keys.find { it.kid == '" + kid + "' }");
    assertNotNull(jwk, "the published JWKS carries no key with kid " + kid);
    assertNull(jwk.get("d"), "the published JWKS must never carry the private half");

    RSAPublicKey published =
        (RSAPublicKey)
            KeyFactory.getInstance("RSA")
                .generatePublic(
                    new RSAPublicKeySpec(
                        unsignedBigEndian((String) jwk.get("n")),
                        unsignedBigEndian((String) jwk.get("e"))));

    int lastDot = jwt.lastIndexOf('.');
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initVerify(published);
    rsa.update(jwt.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII));
    assertTrue(
        rsa.verify(Base64.getUrlDecoder().decode(jwt.substring(lastDot + 1))),
        "the key published at /idp/jwks must be the key that signed the token");
  }

  private static BigInteger unsignedBigEndian(String base64Url) {
    return new BigInteger(1, Base64.getUrlDecoder().decode(base64Url));
  }

  @AfterAll
  static void bothStoryReportsAreComplete() {
    // The extension emits each report in its afterEach, so both are on disk before @AfterAll runs.
    ReportAssertions.assertComplete(CATEGORY, MINTED_SLUG, UserflowReport.PASSED);
    ReportAssertions.assertInteraction(
        CATEGORY,
        MINTED_SLUG,
        CLIENT,
        "qits-platform-idp",
        "GET /idp/.well-known/openid-configuration");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "discovery-read");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "bearer-minted");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "bearer-answered");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "signing-key-published");

    ReportAssertions.assertComplete(CATEGORY, REFUSED_SLUG, UserflowReport.PASSED);
    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "wrong-secret-refused");
    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "unentitled-audience-refused");
    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "bootstrap-doors-open");
  }
}
