package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The self-role rule itself, without a process around it: what a token's {@code groups} is built
 * from, and what a configured role may not be.
 *
 * <p>A plain unit test rather than a {@code @QuarkusTest}, because one case here is unreachable
 * over HTTP on purpose — a duplicate self-role cannot be configured once the namespace is refused,
 * and the deduplication that would absorb it still has to be true.
 */
public class ClientRolesTest {

  @Test
  public void aMintedTokenCarriesTheConfiguredRolesThenTheClientsOwn() {
    assertEquals(
        List.of("qits:system", "qits-platform:system", "clients/prod-qits-projects"),
        List.copyOf(ClientRoles.mintedFor(client("prod-qits-projects", "qits:system", "qits-platform:system"))));
  }

  @Test
  public void aClientWithNoConfiguredRolesStillNamesItself() {
    assertEquals(List.of("clients/dyn-ci-run-4711-abc"), List.copyOf(ClientRoles.mintedFor(client("dyn-ci-run-4711-abc"))));
  }

  @Test
  public void theSelfRoleAppearsOnceHoweverTheRolesWereAssembled() {
    assertEquals(
        List.of("qits:system", "clients/prod-qits-projects"),
        List.copyOf(
            ClientRoles.mintedFor(
                client("prod-qits-projects", "qits:system", "clients/prod-qits-projects"))),
        "a claim's shape must not depend on how its input was built");
  }

  @Test
  public void theReservedNamespaceIsRefusedForAnotherClientAndForTheClientItself() {
    assertThrows(
        OAuthException.class,
        () -> ClientRoles.refuseReserved("prod-qits-ci", List.of("qits:system", "clients/prod-qits-projects")));
    assertThrows(
        OAuthException.class,
        () -> ClientRoles.refuseReserved("prod-qits-ci", List.of("clients/prod-qits-ci")),
        "its own is refused too: it is redundant, and it normalises writing the prefix by hand");
    assertThrows(
        OAuthException.class,
        () -> ClientRoles.refuseReserved("prod-qits-ci", List.of("  clients/prod-qits-projects ")),
        "a configured value is trimmed before it is read, so it is trimmed before it is judged");

    OAuthException refusal =
        assertThrows(
            OAuthException.class,
            () -> ClientRoles.refuseReserved("prod-qits-ci", List.of("clients/anything")));
    assertEquals("invalid_request", refusal.error());
    assertEquals(400, refusal.statusCode());
  }

  @Test
  public void anOrdinaryRoleIsNotRefused() {
    ClientRoles.refuseReserved("prod-qits-ci", List.of("qits:system", "qits-platform:system"));
    ClientRoles.refuseReserved("prod-qits-ci", List.of());
    ClientRoles.refuseReserved("prod-qits-ci", null);
    // The prefix is the whole of the rule — a role that merely mentions it is somebody else's.
    ClientRoles.refuseReserved("prod-qits-ci", List.of("qits:clients/read"));
  }

  private static IdpClient client(String clientId, String... roles) {
    return new IdpClient(clientId, null, List.of(), List.of(roles), Map.of());
  }
}
