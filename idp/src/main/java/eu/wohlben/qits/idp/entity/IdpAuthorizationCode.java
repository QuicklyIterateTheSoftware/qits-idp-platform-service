package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A short-lived, single-use authorization code for the local Git workstation public client.
 *
 * <p>The value delivered through the browser is never stored.  The row keeps only its fingerprint
 * and the three bindings that make a stolen code useless to a different caller: the exact loopback
 * redirect URI, the PKCE S256 challenge, and the user that approved it.
 */
@Entity
@Table(name = "idp_authorization_code")
public class IdpAuthorizationCode extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  @Column(name = "code_hash", nullable = false, length = 255, unique = true)
  public String codeHash;

  @Column(name = "user_id", nullable = false)
  public UUID userId;

  @Column(name = "redirect_uri", nullable = false, length = 2048)
  public String redirectUri;

  @Column(name = "code_challenge", nullable = false, length = 128)
  public String codeChallenge;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  /** Set in the same transaction that creates the refresh-token family. */
  @Column(name = "consumed_at")
  public Instant consumedAt;
}
