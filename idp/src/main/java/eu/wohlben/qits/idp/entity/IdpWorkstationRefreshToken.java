package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One rotating refresh-token link.  Tokens in one family belong to one user workstation grant.
 *
 * <p>A used token is retained rather than deleted.  Seeing it again is replay, at which point the
 * entire family is revoked and neither the thief nor the original workstation can refresh again.
 */
@Entity
@Table(name = "idp_workstation_refresh_token")
public class IdpWorkstationRefreshToken extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  @Column(name = "family_id", nullable = false)
  public UUID familyId;

  @Column(name = "token_hash", nullable = false, length = 255, unique = true)
  public String tokenHash;

  @Column(name = "user_id", nullable = false)
  public UUID userId;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  /** The normal rotation marker. Any second presentation is a family-revoking replay. */
  @Column(name = "used_at")
  public Instant usedAt;

  /** Set by explicit workstation revocation or refresh replay. */
  @Column(name = "revoked_at")
  public Instant revokedAt;
}
