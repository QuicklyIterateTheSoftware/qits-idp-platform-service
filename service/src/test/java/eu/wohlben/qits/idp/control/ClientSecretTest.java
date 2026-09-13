package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;

/**
 * The dual-source rule itself, deterministically — {@link ServiceClients} and {@code
 * IdpServiceClientsControllerTest} exercise it through a live rotation, which cannot wait out the
 * fifteen-minute grace (D4 of {@code service-client-identity-plan.md}) inside a test. This pins the
 * expiry check {@link ClientSecret#matches} makes at authentication time, with a clock a test
 * controls.
 */
public class ClientSecretTest {

  @Test
  public void aDatabaseServiceClientAcceptsItsCurrentHash() {
    ClientSecret secret =
        ClientSecret.serviceClient(null, ClientSecret.hash("current"), null, null);
    assertTrue(secret.matches("current"));
    assertFalse(secret.matches("wrong"));
  }

  @Test
  public void aPreviousHashAuthenticatesWhileItIsStillLive() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            null,
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().plus(15, ChronoUnit.MINUTES));

    assertTrue(secret.matches("current"), "the fresh secret");
    assertTrue(secret.matches("previous"), "the rotated-out one, still inside its grace");
  }

  @Test
  public void aPreviousHashStopsAuthenticatingOnceItsGraceHasPassed() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            null,
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().minus(1, ChronoUnit.SECONDS));

    assertTrue(secret.matches("current"));
    assertFalse(secret.matches("previous"), "the grace window (D4) has closed");
  }

  @Test
  public void eitherMergesAnEnvironmentSecretWithADatabaseHash() {
    ClientSecret environment = ClientSecret.configured("env-secret");
    ClientSecret database = ClientSecret.serviceClient(null, ClientSecret.hash("db-secret"), null, null);

    ClientSecret merged = ClientSecret.either(environment, database);
    assertTrue(merged.matches("env-secret"), "the environment value still authenticates");
    assertTrue(merged.matches("db-secret"), "and the database hash too");
    assertFalse(merged.matches("neither"));
  }

  @Test
  public void aDatabaseOnlyClientHasNoConfiguredValue() {
    ClientSecret secret = ClientSecret.serviceClient(null, ClientSecret.hash("only"), null, null);
    assertFalse(secret.matches(null), "a null candidate never matches");
    assertTrue(secret.usable());
  }
}
