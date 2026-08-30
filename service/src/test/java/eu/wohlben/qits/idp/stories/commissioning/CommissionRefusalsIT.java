package eu.wohlben.qits.idp.stories.commissioning;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.wohlben.qits.idp.stories.support.StoryNetwork;
import eu.wohlben.qits.idp.stories.support.StoryProfile;
import eu.wohlben.qits.idp.stories.support.StoryTarget;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.Network;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkEdge;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.Slugs;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>The blast radius of a leaked commissioned secret is one context, and these four refusals are
 * what keep it there.</b>
 *
 * <p>A commissioned credential is handed to something the platform does not control the inside of —
 * a build step, an agent container, a workspace that runs for days. So the interesting question is
 * not what it can do but what it cannot, and the answers are structural rather than configured:
 *
 * <ul>
 *   <li><b>It cannot make more of itself.</b> A credential able to commission would outlive its own
 *       decommission through the ones it made, and a leak would stop being bounded by one context.
 *       It authenticates here — it has to, so a context can hand its own credential back — and is
 *       then refused 403, which is a different answer from 401 on purpose.
 *   <li><b>It is invisible to every other owner.</b> Another platform service asking to delete it
 *       gets 404 — the same answer as an id that never existed — so nobody maps which services hold
 *       which contexts by probing this endpoint. And a listing is the caller's own; there is no
 *       listing across owners and no way to ask for one.
 *   <li><b>It can hand itself back.</b> The one thing a commissioned credential may do on this
 *       surface is delete <i>itself</i>, so a context that knows it is finishing does not have to go
 *       through its owner.
 *   <li><b>And nothing reaches any of it unauthenticated.</b> The commission API is HTTP Basic
 *       against the caller's existing idp pair — no new audience to configure, no bearer-validation
 *       stack inside the service that issues the bearers — so an unauthenticated call is 401 with
 *       the {@code WWW-Authenticate: Basic} challenge RFC 6749 §5.2 requires.
 * </ul>
 *
 * <p>Three initiators, one route, four statuses. On the wire the only thing that distinguishes them
 * is a Basic header a diagram must never print — which is exactly why every story here names its
 * actor before it calls.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class CommissionRefusalsIT {

  static final String CATEGORY = "commissioning";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "A commissioned credential cannot make more of itself";

  static final String SLUG = Slugs.slug(STORY);

  /** This story's own rows, so no assertion here depends on what another story left in the store. */
  private static final String CONTEXT_KIND = "uf-guard";

  private static final String CONTEXT_ID = "ws-" + System.nanoTime();

  /** Generated values that must appear in no file of the bundle — see {@code @AfterAll}. */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      A workspaces service commissions a credential for a container, and then four callers find
      out what that credential is and is not.

      The container itself asks to commission another. It AUTHENTICATES — it has to, because a
      context has to be able to hand its own credential back — and is refused 403 `access_denied`.
      A credential that could produce more credentials would outlive its own decommission through
      the ones it made, and the blast radius of a leaked build-step secret would stop being one
      build. Only a configured service client may commission.

      Another platform service asks to delete it, and gets 404 — the same answer as an id that
      never existed. The endpoint tells nobody which other services hold which contexts, so a
      compromised service cannot map the platform's live workspaces by probing for ids. Its
      listing, likewise, is its own: there is no listing across owners and no way to ask for one.

      Then the container hands its own credential back and that succeeds — 204, the row is gone,
      and the owner never had to be involved.

      And a caller holding nothing at all is challenged. The commission API authenticates with the
      same `client_secret_basic` pair the token endpoint accepts, checked by the same code, because
      a caller here already holds an idp credential and a second one would only be a second thing
      for a deployment to distribute — so an unauthenticated call gets 401 and the Basic challenge,
      never a hint that the route exists for somebody.
      """)
  void onlyAServiceClientMayCommissionAndOnlyAnOwnerMaySee(Interactions story, Network network) {
    // Rows again: an insert, the reads behind three lookups, and a delete. Declared, because no tap
    // can see a JDBC call and a claim must not render like evidence.
    network.declare(
        NetworkEdge.JDBC,
        StoryTarget.SERVICE,
        "postgres (the idp's own store)",
        "commissioned clients: insert, read, delete");

    // ---- the credential this story is about ------------------------------------------------------
    NetworkCapture.actor(StoryTarget.WORKSPACES);
    JsonPath commissioned =
        StoryTarget.machine(StoryTarget.WORKSPACES, StoryTarget.WORKSPACES_SECRET)
            .contentType(ContentType.JSON)
            .body(
                "{\"contextKind\":\""
                    + CONTEXT_KIND
                    + "\",\"contextId\":\""
                    + CONTEXT_ID
                    + "\"}")
            .when()
            .post(StoryTarget.CLIENTS)
            .then()
            .statusCode(201)
            .body("clientId", startsWith("dyn-"))
            .extract()
            .jsonPath();
    String clientId = commissioned.getString("clientId");
    String secret = commissioned.getString("secret");
    assertNotNull(clientId);
    assertNotNull(secret);
    NEVER_IN_THE_BUNDLE.add(clientId);
    NEVER_IN_THE_BUNDLE.add(secret);
    story
        .note(
            "the workspaces service commissions a credential for one container — the same call the"
                + " minting story tells; here it is the setup for what that credential may not do")
        .as("a-credential-exists-to-be-tested");

    // ---- (a) it may not commission ---------------------------------------------------------------
    NetworkCapture.actor(StoryTarget.CONTAINER);
    StoryTarget.machine(clientId, secret)
        .contentType(ContentType.JSON)
        .body("{\"contextKind\":\"" + CONTEXT_KIND + "\",\"contextId\":\"nested\"}")
        .when()
        .post(StoryTarget.CLIENTS)
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"))
        .body("clientId", nullValue())
        .body("secret", nullValue());
    story
        .note(
            "the container asks to commission another and is refused 403 access_denied — it"
                + " AUTHENTICATED, which is why the code is not 401: a credential that could make"
                + " more credentials would outlive its own decommission through the ones it made,"
                + " and a leaked build-step secret would stop being one build")
        .as("a-commissioned-credential-may-not-commission");

    // ---- (b) another owner cannot see it, and cannot delete it -----------------------------------
    NetworkCapture.actor(StoryTarget.CI);
    StoryTarget.machine(StoryTarget.CI, StoryTarget.CI_SECRET)
        .when()
        .delete(StoryTarget.client(clientId))
        .then()
        .statusCode(404)
        .body("error", equalTo("not_found"));
    StoryTarget.machine(StoryTarget.CI, StoryTarget.CI_SECRET)
        .when()
        .get(StoryTarget.CLIENTS)
        .then()
        .statusCode(200)
        .body("find { it.contextId == '" + CONTEXT_ID + "' }", nullValue());
    story
        .note(
            "another platform service — authenticated, and carrying the same qits-platform:system"
                + " role — gets 404 for a credential it does not own, the SAME answer as an id that"
                + " never existed, so nobody maps which services hold which contexts by probing"
                + " here. And its listing is its own: there is no listing across owners")
        .as("another-owner-sees-nothing-and-deletes-nothing");

    // ---- (c) but the context may hand its own credential back ------------------------------------
    NetworkCapture.actor(StoryTarget.CONTAINER);
    StoryTarget.machine(clientId, secret)
        .when()
        .delete(StoryTarget.client(clientId))
        .then()
        .statusCode(204);
    story
        .note(
            "the container hands its OWN credential back and that succeeds — the one thing a"
                + " commissioned credential may do on this surface, so a context that knows it is"
                + " finishing does not have to go through its owner to stop existing")
        .as("a-context-may-hand-its-own-credential-back");

    // ---- (d) and nothing at all reaches this surface unauthenticated -----------------------------
    NetworkCapture.actor(StoryTarget.UNCREDENTIALED);
    given()
        .contentType(ContentType.JSON)
        .body("{\"contextKind\":\"" + CONTEXT_KIND + "\",\"contextId\":\"anonymous\"}")
        .when()
        .post(StoryTarget.CLIENTS)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        // RFC 6749 §5.2: the challenge rides every 401 here, because the machine surfaces
        // authenticate with a Basic pair and deciding per-request would mean the mapper had to know
        // how the credentials arrived.
        .header("WWW-Authenticate", equalTo("Basic realm=\"qits-platform-idp\""));
    story
        .note(
            "and a caller holding nothing is challenged: the commission API takes the same"
                + " client_secret_basic pair the token endpoint accepts, checked by the same code,"
                + " because a caller here already holds an idp credential — no new audience, no"
                + " bearer-validation stack inside the service that issues the bearers, and no"
                + " second credential for a deployment to distribute")
        .as("an-unauthenticated-caller-is-challenged");
  }

  @AfterAll
  static void theGuardStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // Three initiators against one API, and the same route drawn three ways: 201 for the owner, 403
    // for the credential it made, 401 for nobody at all. The status IS the story.
    in(StoryTarget.WORKSPACES, StoryTarget.posted(StoryTarget.CLIENTS, 201));
    in(StoryTarget.CONTAINER, StoryTarget.posted(StoryTarget.CLIENTS, 403));
    in(StoryTarget.CI, StoryTarget.deleted(StoryTarget.ANY_CLIENT, 404));
    in(StoryTarget.CI, StoryTarget.read(StoryTarget.CLIENTS, 200));
    in(StoryTarget.CONTAINER, StoryTarget.deleted(StoryTarget.ANY_CLIENT, 204));
    in(StoryTarget.UNCREDENTIALED, StoryTarget.posted(StoryTarget.CLIENTS, 401));

    ReportAssertions.assertDeclaredEdge(
        CATEGORY_SLUG,
        SLUG,
        NetworkEdge.JDBC,
        StoryTarget.SERVICE,
        "postgres (the idp's own store)",
        "commissioned clients: insert, read, delete");

    // SEVEN: six refusals-and-permissions plus the declared store. A refusal that had reached
    // anywhere else — an audit sink, a peer to ask about a role — would be an eighth.
    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 7);
    ReportAssertions.assertOnlyEdgesFrom(
        CATEGORY_SLUG,
        SLUG,
        List.of(
            StoryTarget.WORKSPACES,
            StoryTarget.CONTAINER,
            StoryTarget.CI,
            StoryTarget.UNCREDENTIALED,
            StoryTarget.SERVICE));

    for (String step :
        List.of(
            "a-credential-exists-to-be-tested",
            "a-commissioned-credential-may-not-commission",
            "another-owner-sees-nothing-and-deletes-nothing",
            "a-context-may-hand-its-own-credential-back",
            "an-unauthenticated-caller-is-challenged")) {
      ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, step);
    }

    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.WORKSPACES_SECRET);
    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.CI_SECRET);
    for (String value : NEVER_IN_THE_BUNDLE) {
      ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, value);
    }
  }

  private static void in(String actor, String label) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG, SLUG, NetworkEdge.HTTP, actor, StoryTarget.SERVICE, label);
  }
}
