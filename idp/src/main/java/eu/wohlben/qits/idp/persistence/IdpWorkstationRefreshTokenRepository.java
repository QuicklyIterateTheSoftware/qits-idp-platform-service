package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpWorkstationRefreshToken;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@ApplicationScoped
public class IdpWorkstationRefreshTokenRepository
    implements PanacheRepositoryBase<IdpWorkstationRefreshToken, UUID> {

  public IdpWorkstationRefreshToken lockByTokenHash(String tokenHash) {
    return find("tokenHash", tokenHash).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
  }

  public List<IdpWorkstationRefreshToken> listFamiliesForUser(UUID userId) {
    return find("userId = ?1 order by createdAt desc", userId).list();
  }

  public void revokeFamily(UUID familyId, Instant at) {
    update("revokedAt = ?2 where familyId = ?1 and revokedAt is null", familyId, at);
  }
}
