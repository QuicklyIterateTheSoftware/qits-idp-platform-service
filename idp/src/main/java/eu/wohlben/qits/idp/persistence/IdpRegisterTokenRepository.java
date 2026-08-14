package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpRegisterToken;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.UUID;

/** Panache DAO for {@link IdpRegisterToken} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpRegisterTokenRepository
    implements PanacheRepositoryBase<IdpRegisterToken, UUID> {

  /**
   * The token row with this fingerprint, or null. A caller presents a plaintext, never an id, so
   * the hash is the only lookup there is — which is also why the column is unique.
   */
  public IdpRegisterToken findByTokenHash(String tokenHash) {
    return find("tokenHash", tokenHash).firstResult();
  }
}
