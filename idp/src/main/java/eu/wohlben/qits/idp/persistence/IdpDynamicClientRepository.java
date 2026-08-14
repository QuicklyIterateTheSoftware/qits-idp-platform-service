package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

/** Panache DAO for {@link IdpDynamicClient} (keyed by its {@code client_id}). */
@ApplicationScoped
public class IdpDynamicClientRepository
    implements PanacheRepositoryBase<IdpDynamicClient, String> {

  /**
   * One owner's live commissions, oldest first — the reconciliation read. Ordered so a caller
   * comparing the list against its own live contexts sees the longest-lived orphan first.
   */
  public List<IdpDynamicClient> listOwnedBy(String owner) {
    return list("owner = ?1 order by createdAt asc, clientId asc", owner);
  }
}
