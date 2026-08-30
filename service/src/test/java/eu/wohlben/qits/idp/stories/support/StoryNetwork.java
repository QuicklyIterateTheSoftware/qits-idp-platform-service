package eu.wohlben.qits.idp.stories.support;

import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkTaps;

/**
 * <b>The whole capture wiring of this catalogue, in one call</b> — so a story class's {@code
 * @BeforeAll} is one line and no class can wire half of it.
 *
 * <p>There is exactly <b>one feed</b>, and that is this service's shape rather than an omission.
 * {@link NetworkTaps#restAssured} makes every request a story sends an edge {@code <actor> ->
 * qits-platform-idp}, labelled {@code METHOD <scrubbed path> -> <status>} with the status this
 * service really answered. Every sibling repository pairs that tap with a {@code
 * NetworkCapture.source} over some mock's recording, because a service under test has an upstream to
 * stand in for; the idp has none. It validates nothing against an OIDC tenant — it is the tenant —
 * and it dials only the postgres its datasource names, so this tap alone is the whole diagram, with
 * every arrow pointing in.
 *
 * <p>Two consequences fall out of having no cumulative source, and both are simplifications worth
 * naming because the sibling catalogues cannot have them:
 *
 * <ul>
 *   <li><b>Story order is not load-bearing.</b> A cumulative recording is attributed by a cursor, so
 *       traffic produced before the first drain lands in whichever story drains first — which is why
 *       a sibling's boot-owning class pins its order and its edge count. {@link
 *       NetworkCapture#observe} has no such window: an edge is appended at the moment the story's
 *       own call returns, on the story's own thread. Nothing this launched process did before the
 *       first story can land in any diagram, because nothing was watching it.
 *   <li><b>No story has to await a far side.</b> There is no async forward to race the story-end
 *       drain, so no relative-count poll and no boot floor anywhere in this catalogue.
 * </ul>
 *
 * <p>The stories are otherwise order-independent by construction: each names its own {@code
 * contextKind} for the rows it creates and filters listings on it, so the shared store — which has
 * no wire-visible clear, and which the launched process does not clean at start because {@code
 * flyway.clean-at-start} lives in the {@code @QuarkusTest} suite's resources and not in the jar —
 * cannot make one story's assertion depend on another's leftovers.
 *
 * <p>Both calls are idempotent: {@link NetworkTaps#restAssured(String)} installs at most one filter
 * per service name (RestAssured's filter list <i>appends</i>), and the normalizer is a single JVM
 * slot every class sets to the same function. So every story class may call {@link #install()} from
 * its own {@code @BeforeAll} without the diagram doubling an edge.
 */
public final class StoryNetwork {

  private StoryNetwork() {}

  /**
   * Install the incoming tap and the commissioned-id normalizer.
   *
   * <p>The normalizer is composed over {@link eu.wohlben.qits.userflows.Labels#scrub}, never instead
   * of it: the default handles the generated shapes it can recognise, and {@link
   * StoryTarget#normalize} handles the one this service mints that no general rule could — a
   * commissioned client id, which is deliberately readable rather than opaque and is therefore
   * invisible to a scrubber looking for UUIDs and hex.
   */
  public static void install() {
    NetworkTaps.restAssured(StoryTarget.SERVICE);
    NetworkCapture.labelNormalizer(StoryTarget::normalize);
  }
}
