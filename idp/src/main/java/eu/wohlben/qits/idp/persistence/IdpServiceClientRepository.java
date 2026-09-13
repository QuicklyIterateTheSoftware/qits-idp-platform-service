package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpServiceClient;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

/** Panache DAO for {@link IdpServiceClient} (keyed by its {@code client_id}). */
@ApplicationScoped
public class IdpServiceClientRepository implements PanacheRepositoryBase<IdpServiceClient, String> {

  /** Every row, oldest first — what {@code ServiceClients} loads into its cache at start. */
  public List<IdpServiceClient> listAllOrdered() {
    return list("order by createdAt asc, clientId asc");
  }
}
