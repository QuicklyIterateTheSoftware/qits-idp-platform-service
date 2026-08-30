package eu.wohlben.qits.idp.stories.refusals;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.stories.support.StoryNetwork;
import eu.wohlben.qits.idp.stories.support.StoryProfile;
import eu.wohlben.qits.idp.stories.support.StoryTarget;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkEdge;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.Slugs;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>A deployment cannot hand one client another client's identity, and the client that tries mints
 * nothing at all.</b>
 *
 * <p>Every {@code client_credentials} token's {@code groups} ends with {@code clients/<the id in
 * sub>}, computed from the id that just authenticated. Nobody asks for it and nobody can turn it
 * off, which is what lets a resource service write {@code @RolesAllowed("clients/prod-qits-ci")} and
 * know that exactly one caller in the platform can ever reach that door.
 *
 * <p>The whole of that guarantee rests on the namespace being <b>minted and never granted</b>. Roles
 * are otherwise ordinary configuration — {@code qits.idp.client.<id>.roles}, env-overridable like
 * every other key — so without a guard "roles are configuration" would quietly mean "any client may
 * be configured into any other client's identity", and the deployment that did it would look exactly
 * like a deployment that did not.
 *
 * <p>So a {@code roles} line under {@code clients/} is refused where the roles are read, and the
 * client is <b>unusable</b> until it is removed: not a warning, not a filtered claim, but {@code
 * invalid_request} on every request that resolves that client. A broken deployment issues nothing
 * rather than issuing too much, which is the same safe direction as a client shipping with no
 * secret. And because every surface here resolves a client through the one lookup — the token
 * endpoint, the Basic-authenticated machine APIs, and a commissioned credential inheriting its
 * owner's roles — one guard covers all of them.
 *
 * <h2>Why this story costs a client the shipped list does not carry</h2>
 *
 * <p>The guard is on <b>configuration</b>, not on a request: there is no parameter a caller can send
 * that asks for a role. Telling the story at all therefore means a deployment that configured one,
 * which is what {@link StoryTarget#ROLE_THIEF} is — and it is the only invented client in this
 * catalogue. {@link StoryProfile} explains the restatement of {@code qits.idp.clients} that adding it
 * costs.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class ReservedRoleNamespaceIT {

  static final String CATEGORY = "refusals";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "A deployment cannot grant a client another client's identity";

  static final String SLUG = Slugs.slug(STORY);

  /** Generated values that must appear in no file of the bundle — see {@code @AfterAll}. */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      Somebody configures a client with `roles=qits:system,clients/prod-qits-ci` — an ordinary
      configuration line, env-overridable like every other, naming the one role that says "this
      bearer IS prod-qits-ci". If it worked, every door on the platform gated with
      `@RolesAllowed("clients/prod-qits-ci")` would open for it, and the deployment that did it
      would look exactly like a deployment that did not.

      It presents a perfectly good credential pair and gets `invalid_request`, 400. Not a warning,
      not a filtered claim, not a token with the offending role quietly dropped: the client is
      UNUSABLE until the line is removed. A broken deployment issues nothing rather than issuing
      too much — the same safe direction as a client shipping with no secret.

      The refusal is coarse, like every other one here. What names the offending role is the log
      line, because the token endpoint is reached before authentication and the value in that
      config key is a deployment's, not a caller's.

      And then the client whose identity was being reached for mints its own token, and the role
      is right there in it — minted from the id in `sub`, additive to the configured roles,
      granted nowhere. It is held by exactly one client by CONSTRUCTION rather than by grant,
      which is the whole thing the guard exists to keep true.
      """)
  void aRolesLineUnderTheReservedNamespaceMakesItsClientUnusable(Interactions story)
      throws Exception {
    // (a) the misconfigured client. A valid pair, and it mints nothing.
    NetworkCapture.actor(StoryTarget.ROLE_THIEF);
    StoryTarget.form()
        .body(
            StoryTarget.clientCredentials(
                StoryTarget.ROLE_THIEF,
                StoryTarget.ROLE_THIEF_SECRET,
                StoryTarget.DEPLOYMENTS_AUDIENCE))
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        // 400, not 401: the credential was fine. What is wrong is the deployment.
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("access_token", nullValue());
    story
        .note(
            "a client configured with another client's minted self-role presents a perfectly good"
                + " pair and gets invalid_request, 400 — the credential was fine, the deployment is"
                + " not. It is UNUSABLE until the line is removed: not a warning and not a filtered"
                + " claim, because a broken deployment must issue nothing rather than too much")
        .as("a-reserved-role-makes-its-client-unusable");

    // (b) and the identity it was reaching for is minted, not granted.
    NetworkCapture.actor(StoryTarget.CI);
    String token =
        StoryTarget.form()
            .body(
                StoryTarget.clientCredentials(
                    StoryTarget.CI, StoryTarget.CI_SECRET, StoryTarget.DEPLOYMENTS_AUDIENCE))
            .when()
            .post(StoryTarget.TOKEN)
            .then()
            .statusCode(200)
            .body("access_token", notNullValue())
            .extract()
            .path("access_token");
    NEVER_IN_THE_BUNDLE.add(token);

    NetworkCapture.actor(StoryTarget.VALIDATOR);
    JwtClaims claims = PublishedJwks.verify(token, StoryTarget.DEPLOYMENTS_AUDIENCE);
    List<String> groups = claims.getStringListClaimValue("groups");
    assertEquals(
        List.of(
            StoryTarget.SYSTEM_ROLE,
            StoryTarget.PLATFORM_SYSTEM_ROLE,
            StoryTarget.selfRoleOf(StoryTarget.CI)),
        groups,
        "the configured roles, then the self-role stamped from the id in sub");
    assertFalse(
        groups.contains(StoryTarget.selfRoleOf(StoryTarget.ROLE_THIEF)),
        "and nothing of the client that tried to reach for this one");
    story
        .note(
            "meanwhile the client whose identity was being reached for mints its own token, and the"
                + " role is right there — stamped from the id in sub, additive to the configured"
                + " roles, and grantable nowhere. A role naming one client is held by exactly that"
                + " client by CONSTRUCTION rather than by grant, which is what lets a resource"
                + " service gate a route on it and know one caller can reach the door")
        .as("the-self-role-is-minted-from-the-id-that-authenticated");
  }

  @AfterAll
  static void theReservedNamespaceStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // The same route, twice, from two clients — 400 for the one a deployment broke, 200 for the one
    // it was reaching for. Plus the JWKS read that makes the second half a proof rather than a look
    // at a decoded body.
    edge(
        StoryTarget.ROLE_THIEF, StoryTarget.posted(StoryTarget.TOKEN, 400));
    edge(StoryTarget.CI, StoryTarget.posted(StoryTarget.TOKEN, 200));
    edge(StoryTarget.VALIDATOR, StoryTarget.read(StoryTarget.JWKS, 200));

    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 3);
    ReportAssertions.assertOnlyEdgesFrom(
        CATEGORY_SLUG,
        SLUG,
        List.of(StoryTarget.ROLE_THIEF, StoryTarget.CI, StoryTarget.VALIDATOR));

    // Both clients are static, so neither the refusal nor the mint opened a connection — and no
    // peer was asked about a role either, because there is nobody to ask: roles are configuration
    // and the guard is where they are read.
    ReportAssertions.assertNoEdgesFrom(CATEGORY_SLUG, SLUG, StoryTarget.SERVICE);

    ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, "a-reserved-role-makes-its-client-unusable");
    ReportAssertions.assertStepId(
        CATEGORY_SLUG, SLUG, "the-self-role-is-minted-from-the-id-that-authenticated");

    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.CI_SECRET);
    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.ROLE_THIEF_SECRET);
    for (String value : NEVER_IN_THE_BUNDLE) {
      ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, value);
    }
  }

  private static void edge(String actor, String label) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG, SLUG, NetworkEdge.HTTP, actor, StoryTarget.SERVICE, label);
  }
}
