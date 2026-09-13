package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpServiceClientSeed;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

/** Panache DAO for the one-row {@link IdpServiceClientSeed} marker. */
@ApplicationScoped
public class IdpServiceClientSeedRepository
    implements PanacheRepositoryBase<IdpServiceClientSeed, Short> {

  /** The row's one fixed id. */
  public static final short ID = 1;

  /** Whether the marker row exists — whether seeding has already run, ever. */
  public boolean seeded() {
    return findById(ID) != null;
  }
}
