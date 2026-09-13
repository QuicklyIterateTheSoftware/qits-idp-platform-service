package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The fixed code map itself, without a process around it (D3/D12 of
 * {@code service-client-identity-plan.md}: a commission's roles are code, never configuration).
 * {@code CommissionedGitRefsTest} checks the same lines through minted tokens end to end.
 */
public class CommissionRolesTest {

  @Test
  public void eachShippedKindHasItsFixedRole() {
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("workspace"));
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("agent-container"));
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("refinement"));
    assertEquals(List.of("qits:ci-run"), CommissionRoles.forKind("ci-run"));
  }

  @Test
  public void anUnknownKindGetsNoRoleAtAll() {
    // D12: unknown kind -> no role, not a refusal — the credential still mints, with only its own
    // clients/<id> self-role.
    assertEquals(List.of(), CommissionRoles.forKind("some-other-kind"));
    assertEquals(List.of(), CommissionRoles.forKind(null));
    assertEquals(List.of(), CommissionRoles.forKind(""));
    // Case matters: the shipped map is keyed on the exact lowercase spelling.
    assertEquals(List.of(), CommissionRoles.forKind("Workspace"));
  }
}
