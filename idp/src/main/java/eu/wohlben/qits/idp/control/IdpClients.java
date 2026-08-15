package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.Config;

/**
 * The static client registry, read from config.
 *
 * <p>Config is the whole registry in phase 1: {@code qits.idp.clients} lists the ids that exist and
 * {@code qits.idp.client.<id>.*} holds each one's secret, audiences and granted claims. Every key
 * is env-overridable by the usual mangling, which is what lets a deployment set a real secret
 * without a file.
 *
 * <p><b>The list is checked before any key is built.</b> A {@code client_id} arrives from an
 * unauthenticated request and is concatenated into a config key; refusing an id that is not on the
 * list first is what keeps a caller from probing the key namespace.
 *
 * <p>Nothing is cached. A client is four config lookups, the token endpoint is not a hot path, and
 * a cache here would only add a question about when a changed secret takes effect.
 *
 * <p>This is the <b>static</b> half of the registry. Commissioned clients are rows and live in
 * {@link DynamicClients}; {@link ClientRegistry} asks this one first, always.
 */
@ApplicationScoped
public class IdpClients {

  static final String CLIENTS_KEY = "qits.idp.clients";
  static final String CLIENT_PREFIX = "qits.idp.client.";

  /** Looked up per key rather than {@code @ConfigProperty}: the keys carry the client id. */
  @Inject Config config;

  /** The configured client ids, in the order they are listed. */
  public List<String> ids() {
    return config.getOptionalValues(CLIENTS_KEY, String.class).orElse(List.of());
  }

  /** The client with this id, or empty when there is none. */
  public Optional<IdpClient> find(String clientId) {
    if (clientId == null || clientId.isBlank() || !ids().contains(clientId)) {
      return Optional.empty();
    }
    String prefix = CLIENT_PREFIX + clientId + ".";
    return Optional.of(
        new IdpClient(
            clientId,
            ClientSecret.configured(
                config.getOptionalValue(prefix + "secret", String.class).orElse(null)),
            config.getOptionalValues(prefix + "audiences", String.class).orElse(List.of()),
            config.getOptionalValues(prefix + "roles", String.class).orElse(List.of()),
            claims(prefix)));
  }

  private Map<String, String> claims(String prefix) {
    // LinkedHashMap so the token's claim order follows ClaimNames.GRANTABLE rather than a hash.
    Map<String, String> granted = new LinkedHashMap<>();
    for (String name : ClaimNames.GRANTABLE) {
      config
          .getOptionalValue(prefix + "claims." + name, String.class)
          .filter(value -> !value.isBlank())
          .ifPresent(value -> granted.put(name, value.trim()));
    }
    // unmodifiableMap, not Map.copyOf: the copy would drop the insertion order this builds.
    return Collections.unmodifiableMap(granted);
  }
}
