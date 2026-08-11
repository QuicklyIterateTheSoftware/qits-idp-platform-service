package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link SigningKeys#reload()} holds through a postgres cutover instead of reporting one as a
 * failed rotation.
 *
 * <p>Two callers reach it and both would answer badly: the boot load fails the process, and a
 * rotation told "no database" while the database is coming back leaves the operator believing the
 * new key was refused. Reading a key is neither of those — {@code signing()} and {@code
 * published()} take the volatile cache and touch postgres not at all, which is why this is the only
 * seam in this service worth a retry.
 *
 * <p>The other half of the wrap is a placement, and it cannot be asserted from out here: the retry
 * sits <b>outside</b> the {@code synchronized} on {@code loadOnce()}, so an attempt takes the lock
 * and releases it before the pause. What this test does pin is that the guard survived the move — a
 * reload that retries still adds no key row.
 */
@QuarkusTest
@TestProfile(SigningKeyCutoverTest.OneLostConnection.class)
public class SigningKeyCutoverTest {

  /** Enables the failing key table for this class alone. */
  public static class OneLostConnection implements QuarkusTestProfile {
    @Override
    public Set<Class<?>> getEnabledAlternatives() {
      return Set.of(ConnectionLosingSigningKeyRows.class);
    }
  }

  @Inject SigningKeys signingKeys;

  @Inject ConnectionLosingSigningKeyRows rows;

  @Inject IdpSigningKeyRepository repository;

  @BeforeEach
  public void healthy() {
    rows.loseTheConnection(0);
  }

  @Test
  public void aReloadAnswersAfterTheReadLosesItsConnection() {
    String kidBefore = signingKeys.signing().kid();

    rows.loseTheConnection(1);
    assertEquals(kidBefore, signingKeys.reload().signing().kid(), "the kid must survive a cutover");
    assertEquals(
        0, rows.unspent(), "the armed failure was never reached — the read did not go through");
    assertEquals(
        1,
        QuarkusTransaction.requiringNew().call(() -> repository.count()),
        "a retried reload must not generate a second key");
  }
}
