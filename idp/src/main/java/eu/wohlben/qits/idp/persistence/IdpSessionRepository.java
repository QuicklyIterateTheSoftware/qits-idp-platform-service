package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpSession;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.UUID;

/** Panache DAO for {@link IdpSession} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpSessionRepository implements PanacheRepositoryBase<IdpSession, UUID> {

  /**
   * The session with this cookie fingerprint, or null. Introspection arrives holding a cookie value
   * and nothing else, so this is the only read there is — and the column is unique so it is one row.
   *
   * <p>It answers a revoked or expired row too. Deciding whether a session is <b>live</b> is the
   * caller's, because that is a comparison against the clock rather than a property of the row.
   */
  public IdpSession findByTokenHash(String tokenHash) {
    return find("tokenHash", tokenHash).firstResult();
  }
}
