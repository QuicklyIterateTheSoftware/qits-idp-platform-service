package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpAuthorizationCode;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.util.UUID;

/** Authorization-code lookup is locked so two simultaneous exchanges cannot both win. */
@ApplicationScoped
public class IdpAuthorizationCodeRepository
    implements PanacheRepositoryBase<IdpAuthorizationCode, UUID> {

  public IdpAuthorizationCode lockByCodeHash(String codeHash) {
    return find("codeHash", codeHash).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
  }
}
