package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * How a deployment overrides the roles the jar ships per kind. The shipped lines sit at ordinal 100
 * (META-INF/microprofile-config.properties); a deployment's environment sits above them. {@code
 * CommissionedGitRefsTest} checks the shipped lines themselves through minted tokens.
 */
public class CommissionRolesTest {

  private static final Map<String, String> SHIPPED =
      Map.of(
          CommissionRoles.PREFIX + "workspace", "qits:agent",
          CommissionRoles.PREFIX + "ci-run", "qits:ci-run");

  @Test
  public void aShippedLineGivesItsKindItsRoles() {
    CommissionRoles roles = over(Map.of());

    assertEquals(Optional.of(List.of("qits:agent")), roles.forKind("workspace"));
    assertEquals(Optional.of(List.of("qits:ci-run")), roles.forKind("ci-run"));
  }

  @Test
  public void aKindWithNoLineGetsItsOwnersRoles() {
    assertEquals(Optional.empty(), over(Map.of()).forKind("some-other-kind"));
  }

  @Test
  public void aDeploymentValueReplacesTheShippedOne() {
    CommissionRoles roles = over(Map.of(CommissionRoles.PREFIX + "workspace", "qits:agent,x:y"));

    assertEquals(Optional.of(List.of("qits:agent", "x:y")), roles.forKind("workspace"));
  }

  @Test
  public void anEmptyDeploymentValueGivesTheKindItsOwnersRolesAgain() {
    CommissionRoles roles = over(Map.of(CommissionRoles.PREFIX + "workspace", ""));

    assertEquals(Optional.empty(), roles.forKind("workspace"), "the way back, one kind at a time");
    assertEquals(Optional.of(List.of("qits:ci-run")), roles.forKind("ci-run"), "the others stay");
  }

  @Test
  public void aMalformedKindBuildsNoKey() {
    assertEquals(Optional.empty(), over(Map.of()).forKind("Workspace"));
    assertEquals(Optional.empty(), over(Map.of()).forKind(null));
  }

  private static CommissionRoles over(Map<String, String> deployment) {
    CommissionRoles roles = new CommissionRoles();
    roles.config =
        new SmallRyeConfigBuilder()
            .withSources(new PropertiesConfigSource(SHIPPED, "shipped", 100))
            .withSources(new PropertiesConfigSource(deployment, "deployment", 300))
            .build();
    return roles;
  }
}
