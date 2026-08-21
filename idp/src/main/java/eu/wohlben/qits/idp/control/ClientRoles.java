package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;

/**
 * The roles a client bearer carries: the ones the deployment configured, plus the one this service
 * writes itself.
 *
 * <p><b>Every client token names its own client.</b> {@code clients/<client-id>} is stamped into
 * the {@code groups} claim of every {@code client_credentials} token, additive to the configured
 * roles. Nobody asks for it, nobody can turn it off, and it is computed from the id that just
 * authenticated — so a role naming one client is held by exactly that client, by construction
 * rather than by grant. That is what lets a resource service write
 * {@code @RolesAllowed("clients/prod-qits-projects")} and know the door opens for one caller only.
 * The commissioned credentials get theirs the same way, for free.
 *
 * <p><b>A commissioned client is issued its owner's configured roles, never its owner's
 * self-role.</b> The stamp is made from the id in the token's {@code sub}, so a credential
 * commissioned by qits-projects carries {@code clients/dyn-…} — its own — and cannot reach a door
 * held open for qits-projects itself. That falls out of the mechanism; there is no rule to keep.
 *
 * <p><b>So the namespace is reserved.</b> A configured role under {@link #SELF_PREFIX} is refused
 * wherever roles are configured — including a client naming its own, which would be redundant and
 * would normalise writing the prefix by hand. Without that guard, "roles are configuration" would
 * quietly mean "any client may be granted any other client's identity", which is the whole of what
 * the self-role is for.
 *
 * <p>User credentials get no self-role: a session belongs to a person and a workstation token is
 * deliberately not an ordinary identity either. This is a machine-client feature and lives on the
 * one path that mints to a client credential, {@link TokenService#clientCredentials}.
 */
public final class ClientRoles {

  private static final Logger LOG = Logger.getLogger(ClientRoles.class);

  /**
   * The reserved namespace. Everything under it is minted here and configurable nowhere — the
   * slash keeps it out of the {@code $app:$resource:$role} shape every configured role has.
   */
  public static final String SELF_PREFIX = "clients/";

  private ClientRoles() {}

  /** The role that names exactly one client. */
  public static String selfRoleOf(String clientId) {
    return SELF_PREFIX + clientId;
  }

  /**
   * The client's configured roles, then its self-role — the {@code groups} claim of a minted token.
   *
   * <p>A {@link LinkedHashSet}, so the configured order is what a reader sees and a self-role that
   * somehow arrived twice appears once. Configuration cannot produce that duplicate ({@link
   * #refuseReserved} refuses the prefix outright); deduplicating anyway costs nothing and keeps the
   * claim's shape independent of how the roles were assembled.
   */
  public static Set<String> mintedFor(IdpClient client) {
    Set<String> roles = new LinkedHashSet<>(client.roles());
    roles.add(selfRoleOf(client.clientId()));
    return roles;
  }

  /**
   * Refuse configured roles in the reserved namespace — a foreign client's self-role and the
   * client's own alike.
   *
   * <p>The refusal is coarse to the caller, like every other one here: the offending value is a
   * deployment's, and the token endpoint is reached before authentication, so what names the role
   * is the log line and not the response.
   *
   * @throws OAuthException {@code invalid_request} (400)
   */
  public static void refuseReserved(String clientId, List<String> configuredRoles) {
    if (configuredRoles == null) {
      return;
    }
    for (String role : configuredRoles) {
      if (role != null && role.trim().startsWith(SELF_PREFIX)) {
        // The client id is bounded by LoggableClientId; the role value is not written at all —
        // it comes from a config key or an environment variable, so its length and its control
        // characters are nobody's promise. Naming the client and the rule is enough to find it.
        LOG.errorf(
            "client %s configures a role under %s, which is minted here and granted nowhere",
            LoggableClientId.of(clientId), SELF_PREFIX);
        throw OAuthException.invalidRequest(
            "roles under "
                + SELF_PREFIX
                + " are reserved: the idp stamps "
                + SELF_PREFIX
                + "<client-id> on every client token it mints, so no client configures one");
      }
    }
  }
}
