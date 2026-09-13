package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The fixed roles of a commissioned credential, by its context kind (D12 of
 * {@code service-client-identity-plan.md}: roles are code, not configuration).
 *
 * <p><b>A commissioned credential no longer inherits its owner's roles.</b> Under the open calling
 * model {@code qits:system} is for service-to-service calls, and a commission is not a service — it
 * is a dynamic context a service provisioned, so it gets the kind's own role or none at all. Four
 * kinds carry a role: {@code workspace}, {@code agent-container} and {@code refinement} get {@code
 * qits:agent}; {@code ci-run} gets {@code qits:ci-run}. <b>Every other kind — including one this
 * service has never heard of — gets no role</b>, only its own {@code clients/<id>} self-role, and
 * that is deliberate rather than a refusal: keeping this a plain map, with no reserved-namespace
 * check needed, is what {@code D12} bought by making an unknown kind harmless instead of an error a
 * test has to route around.
 *
 * <p>Only the roles are fixed here. A commission's claims are its own (D3, no owner merge — see
 * {@code CommissionedClaims}), and its audience rule follows its owner's (see {@link
 * IdpClient.AudienceSource}). Both are {@link ClientRegistry}'s.
 */
public final class CommissionRoles {

  private static final List<String> AGENT = List.of("qits:agent");

  private static final List<String> CI_RUN = List.of("qits:ci-run");

  private static final Map<String, List<String>> SHIPPED =
      Map.of(
          "workspace", AGENT,
          "agent-container", AGENT,
          "refinement", AGENT,
          "ci-run", CI_RUN);

  private CommissionRoles() {}

  /** This kind's fixed role, or empty when it has none (D12) — never null. */
  public static List<String> forKind(String contextKind) {
    if (contextKind == null) {
      return List.of();
    }
    return Optional.ofNullable(SHIPPED.get(contextKind)).orElse(List.of());
  }
}
