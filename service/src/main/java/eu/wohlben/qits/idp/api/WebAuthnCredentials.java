package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Users;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord.RequiredPersistedData;
import io.quarkus.security.webauthn.WebAuthnUserProvider;
import io.smallrye.common.annotation.Blocking;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Set;

/**
 * The bridge between quarkus-security-webauthn and this service's store: how the extension looks a
 * passkey up, and nothing more.
 *
 * <p><b>Only the read half is implemented, and that is the design.</b> {@code store} and {@code
 * update} exist on this interface for the extension's <b>built-in</b> register and login endpoints,
 * which are off here — writing a credential is part of a registration that also spends a token,
 * grants roles and opens a session, all in one transaction, and an interface method the extension
 * calls on its own terms cannot be part of that. So {@link IdpAuthController} verifies the ceremony
 * and hands the result to {@link Users}, and the two default no-op methods stay defaults.
 *
 * <p><b>{@code findByCredentialId} fails rather than returning nothing</b>, which is the contract
 * the interface states and the login path depends on: {@code WebAuthnSecurity.login} chains off it,
 * so an empty item would be a silent success with no credential to verify against.
 *
 * <p>{@code @Blocking} is load-bearing. The extension inspects this class for the annotation and,
 * finding none, would assume it may be called on the event loop — where these methods open a
 * database connection. Saying so puts the lookups on a worker thread wherever they are reached
 * from.
 */
@ApplicationScoped
@Blocking
public class WebAuthnCredentials implements WebAuthnUserProvider {

  @Inject Users users;

  @Override
  public Uni<List<WebAuthnCredentialRecord>> findByUsername(String username) {
    return Uni.createFrom()
        .item(() -> users.credentialsOf(username).stream().map(WebAuthnCredentials::toRecord).toList());
  }

  @Override
  public Uni<WebAuthnCredentialRecord> findByCredentialId(String credentialId) {
    return Uni.createFrom()
        .item(() -> users.credentialById(credentialId).orElse(null))
        .onItem()
        .ifNull()
        .failWith(() -> new IllegalArgumentException("no such credential"))
        .map(WebAuthnCredentials::toRecord);
  }

  /**
   * The roles the extension would attach to an identity it built itself. Nothing here asks it to —
   * this service issues its own session and reports roles through introspection — but answering
   * truthfully costs one query and keeps the two views of an account from disagreeing.
   */
  @Override
  public Set<String> getRoles(String username) {
    return users.byUsername(username).map(account -> Set.copyOf(account.roles())).orElse(Set.of());
  }

  private static WebAuthnCredentialRecord toRecord(Users.Credential credential) {
    return WebAuthnCredentialRecord.fromRequiredPersistedData(
        new RequiredPersistedData(
            credential.username(),
            credential.credentialId(),
            credential.aaguid(),
            credential.publicKey(),
            credential.publicKeyAlgorithm(),
            credential.counter()));
  }
}
