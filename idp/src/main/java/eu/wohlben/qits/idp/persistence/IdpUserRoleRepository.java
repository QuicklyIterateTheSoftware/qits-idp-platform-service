package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpUserRole;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.UUID;

/** Panache DAO for {@link IdpUserRole}, keyed by the (user, role) pair. */
@ApplicationScoped
public class IdpUserRoleRepository
    implements PanacheRepositoryBase<IdpUserRole, IdpUserRole.Key> {

  /**
   * One account's roles, in Java's natural string order.
   *
   * <p>The order is not cosmetic: introspection answers this list, and the edge joins it into one
   * comma-separated {@code X-Qits-Roles} header that it caches. A set that came back in a different
   * order on a different read would change that header for no reason.
   *
   * <p><b>Sorted here rather than with an {@code order by}, and that was measured.</b> Postgres
   * orders by the database's collation, which at its primary strength ignores punctuation — so
   * {@code qits:admin} sorts <i>before</i> {@code qits-platform:admin} there and after it in Java.
   * Neither is wrong, but only one of them is the same on every installation, and this list leaves
   * the service. Two roles is not a page of rows to sort in memory, and the day it is, this is the
   * method that grows a collation-pinned index rather than the caller growing a surprise.
   */
  public List<String> rolesOf(UUID userId) {
    return find("userId = ?1", userId).stream().map(row -> row.role).sorted().toList();
  }
}
