package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpUser;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.UUID;

/** Panache DAO for {@link IdpUser} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpUserRepository implements PanacheRepositoryBase<IdpUser, UUID> {

  /** The account with this login name, or null. The unique index is what makes it at most one. */
  public IdpUser findByUsername(String username) {
    return find("username", username).firstResult();
  }
}
