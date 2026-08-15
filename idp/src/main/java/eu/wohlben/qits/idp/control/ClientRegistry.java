package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.DynamicClients.StoredClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Every client this idp knows, from both halves: the static service clients in config and the
 * commissioned clients in {@code idp_client}.
 *
 * <p><b>Config is asked first, always.</b> A static id therefore cannot be shadowed by a row, and
 * that ordering is the collision answer rather than a uniqueness check somewhere: whatever ends up
 * in the store, the names services are dialed by keep meaning what the deployment configured.
 * Commissioned ids carry {@link DynamicClients#ID_PREFIX} on top of that, so the two namespaces do
 * not overlap in the first place.
 *
 * <p><b>A commissioned client is issued its owner's audiences and claims</b>, read here at mint
 * time rather than copied into the row. Full access for now, which is the plan's decision
 * (2026-08-14): a credential commissioned by qits-ci can do what qits-ci can do, so nothing has to
 * be enumerated before the credentials can replace the static ones. Two consequences worth knowing:
 * narrowing an owner's audiences narrows every credential it commissioned, at once; and an owner
 * removed from {@code qits.idp.clients} leaves its commissioned clients able to authenticate and
 * entitled to nothing, which is refused as {@code invalid_target}. Per-context scoping is the
 * declared follow-up and is what will put a narrower set on the row itself.
 */
@ApplicationScoped
public class ClientRegistry {

  private static final Logger LOG = Logger.getLogger(ClientRegistry.class);

  @Inject IdpClients staticClients;

  @Inject DynamicClients dynamicClients;

  /** The client with this id, static or commissioned, or empty when there is none. */
  public Optional<IdpClient> find(String clientId) {
    Optional<IdpClient> configured = staticClients.find(clientId);
    if (configured.isPresent()) {
      return configured;
    }
    return dynamicClients.find(clientId).map(this::asClient);
  }

  /**
   * Whether this id is a configured service client rather than a commissioned one.
   *
   * <p>The commission endpoints ask, because <b>a commissioned client may not commission</b>: the
   * ability to mint credentials belongs to the platform's own services, and a credential handed to
   * a build step or an agent container must not be able to produce more of itself. That is what
   * keeps the blast radius of a leaked commissioned secret at one context.
   */
  public boolean isStatic(String clientId) {
    return staticClients.find(clientId).isPresent();
  }

  /**
   * Authenticate a presented id and secret, or refuse.
   *
   * <p>One refusal for three causes — unknown id, no secret configured, wrong secret. The caller
   * learns only that it did not authenticate; the log line is where the difference lives.
   *
   * @throws OAuthException {@code invalid_client} (401)
   */
  public IdpClient authenticate(String clientId, String secret) {
    IdpClient client = find(clientId).orElse(null);
    if (client == null || !client.secretMatches(secret)) {
      LOG.warnf(
          "client authentication failed for %s: %s",
          LoggableClientId.of(clientId),
          client == null
              ? "unknown client"
              : (client.usable() ? "wrong secret" : "no secret configured"));
      throw OAuthException.invalidClient("client authentication failed");
    }
    return client;
  }

  private IdpClient asClient(StoredClient stored) {
    IdpClient owner = staticClients.find(stored.owner()).orElse(null);
    return new IdpClient(
        stored.clientId(),
        ClientSecret.stored(stored.secretHash()),
        owner == null ? List.of() : owner.audiences(),
        owner == null ? List.of() : owner.roles(),
        owner == null ? Map.of() : owner.claims());
  }
}
