package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The two public-client audiences on an installation whose environment is not prod.
 *
 * <p>The deployer gives every app {@code QITS_ENVIRONMENT}. The workstation's githost audience
 * follows it, because the githost's wire alias does. The CLI's audience does not: it is one
 * platform-wide name. Both are read at boot, so this costs its own application start.
 */
@QuarkusTest
@TestProfile(EnvironmentAudiencesTest.DevEnvironment.class)
public class EnvironmentAudiencesTest {

  public static class DevEnvironment implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("QITS_ENVIRONMENT", "dev");
    }
  }

  private static final String WORKSTATION = "qits-git-workstation";
  private static final String WORKSTATION_REDIRECT = "http://127.0.0.1:38473/callback";
  private static final String CLI = "qits-cli";
  private static final String CLI_PAGE = "http://localhost:8080/idp/connect/cli";
  private static final String VERIFIER =
      "env-verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

  @Inject IdpUserRepository users;

  @Inject Sessions sessions;

  @Test
  public void theWorkstationAudienceFollowsTheEnvironment() throws Exception {
    Sessions.Opened session = signedInSession();

    // The prod alias is not this installation's githost, so /authorize refuses it.
    workstationAuthorize(session.token(), "prod-qits-githost")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    Response approved = workstationAuthorize(session.token(), "dev-qits-githost");
    approved.then().statusCode(303);
    String code = CliOAuthTest.param(approved.getHeader("Location"), "code");

    String access =
        exchange(WORKSTATION, WORKSTATION_REDIRECT, code).jsonPath().getString("access_token");
    JwtClaims claims = PublishedJwks.verify(access, "dev-qits-githost");
    assertEquals(List.of("dev-qits-githost"), claims.getAudience());
  }

  @Test
  public void theCliAudienceIsTheSameInEveryEnvironment() throws Exception {
    Sessions.Opened session = signedInSession();
    Response approved =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, session.token())
            .queryParam("response_type", "code")
            .queryParam("client_id", CLI)
            .queryParam("redirect_uri", CLI_PAGE)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .when()
            .get("/idp/authorize");
    approved.then().statusCode(303);
    String code = CliOAuthTest.param(approved.getHeader("Location"), "code");

    String access = exchange(CLI, CLI_PAGE, code).jsonPath().getString("access_token");
    JwtClaims claims = PublishedJwks.verify(access, "qits-platform");
    assertEquals(List.of("qits-platform"), claims.getAudience());
  }

  private Response workstationAuthorize(String sessionToken, String audience) {
    return given()
        .redirects()
        .follow(false)
        .cookie(SessionCookie.NAME, sessionToken)
        .queryParam("response_type", "code")
        .queryParam("client_id", WORKSTATION)
        .queryParam("redirect_uri", WORKSTATION_REDIRECT)
        .queryParam("code_challenge", challenge(VERIFIER))
        .queryParam("code_challenge_method", "S256")
        .queryParam("audience", audience)
        .when()
        .get("/idp/authorize");
  }

  private static Response exchange(String clientId, String redirectUri, String code) {
    Response response =
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "authorization_code")
            .formParam("client_id", clientId)
            .formParam("code", code)
            .formParam("redirect_uri", redirectUri)
            .formParam("code_verifier", VERIFIER)
            .when()
            .post("/idp/token");
    response.then().statusCode(200);
    return response;
  }

  private Sessions.Opened signedInSession() {
    UUID id = UUID.randomUUID();
    String username = "env-" + id;
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = username;
              row.createdAt = Instant.now();
              users.persist(row);
              IdpUserRole role = new IdpUserRole();
              role.userId = id;
              role.role = "qits:admin";
              role.createdAt = Instant.now();
              role.persist();
            });
    return sessions.open(new Users.Account(id, username, List.of("qits:admin")));
  }

  private static String challenge(String verifier) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (Exception impossible) {
      throw new AssertionError(impossible);
    }
  }
}
