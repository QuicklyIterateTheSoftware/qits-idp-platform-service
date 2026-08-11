package eu.wohlben.qits.idp;

import eu.wohlben.qits.archrules.DatasourceBaselineRules;
import org.junit.jupiter.api.Test;

/**
 * The `idp` datasource carries the platform's resilience baseline: the patient driver, validation at
 * borrow, and a 15s acquisition timeout. The rule reads the config rather than the code, and it
 * names each missing line.
 *
 * <p>It lives in {@code service/} because this module's classpath is the deployable's whole config —
 * the datasource itself is declared in the {@code idp} jar, and a service that adds a second one is
 * judged here without anything being added to this class.
 *
 * <p>A cutover of the tier's postgres is what the baseline exists for, and this is the service it
 * matters most for: every other one asks this one for a token.
 * {@code docs/project-setup-quinoa-angular.md} in the superproject has the measurements.
 */
class DatasourceBaselineTest {

  @Test
  void everyPostgresDatasourceCarriesTheBaseline() {
    DatasourceBaselineRules.assertBaseline();
  }
}
