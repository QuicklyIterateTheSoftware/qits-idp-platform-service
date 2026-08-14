package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpWebAuthnCredential;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.UUID;

/** Panache DAO for {@link IdpWebAuthnCredential} (keyed by its base64url credential id). */
@ApplicationScoped
public class IdpWebAuthnCredentialRepository
    implements PanacheRepositoryBase<IdpWebAuthnCredential, String> {

  /** Every authenticator registered for one account — what the login ceremony's options read. */
  public List<IdpWebAuthnCredential> listForUser(UUID userId) {
    return list("userId = ?1 order by createdAt asc, credentialId asc", userId);
  }
}
