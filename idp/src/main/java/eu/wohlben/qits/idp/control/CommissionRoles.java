package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Optional;
import org.eclipse.microprofile.config.Config;

/**
 * The roles of a commissioned credential, when its context kind has roles of its own:
 * {@code qits.idp.commission.roles.<contextKind>=<role>,<role>}.
 *
 * <p><b>No line, or an empty one, means the owner's roles.</b> That is what every commission got
 * before this key existed, and what every kind gets until a deployment sets one. Phase 4 of {@code
 * principal-bound-git-refs-plan.md} (qits superproject) sets the agent kinds to {@code qits:agent},
 * so an agent stops inheriting {@code qits:system} from the service that commissioned it. Nothing
 * sets the key yet.
 *
 * <p>Only the roles change. Audiences stay the owner's; claims stay the owner's plus the
 * commission's own. {@link ClientRegistry} refuses a {@code clients/…} role here, as it does on a
 * static client ({@link ClientRoles}).
 */
@ApplicationScoped
public class CommissionRoles {

  static final String PREFIX = "qits.idp.commission.roles.";

  /** Looked up per key rather than {@code @ConfigProperty}: the key carries the context kind. */
  @Inject Config config;

  /** The configured roles for this kind, or empty when the owner's roles apply. */
  public Optional<List<String>> forKind(String contextKind) {
    // The kind becomes part of a config key, so only a well-formed kind builds one. Anything else
    // (a row edited by hand) gets the owner's roles, as every row did before this key existed.
    if (!DynamicClients.isContextKind(contextKind)) {
      return Optional.empty();
    }
    return config.getOptionalValues(PREFIX + contextKind, String.class).map(List::copyOf);
  }
}
