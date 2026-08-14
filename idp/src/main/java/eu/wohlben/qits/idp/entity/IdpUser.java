package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One account. Deliberately the smallest row that can be an identity: an id, a name, and an
 * optional password.
 *
 * <p><b>No role column.</b> Roles are {@link IdpUserRole}, an assignment table, from day one —
 * admins and plain users are told apart by a set, and a set does not belong in a column. What a
 * role permits is a later plan; this context stores the strings and interprets none of them.
 *
 * <p><b>{@link #passwordHash} is null for a passwordless account</b>, which is the default one.
 * Registration runs the WebAuthn ceremony so an authenticator holds the key; a password is the
 * optional second factor a user may add afterwards, and the fallback for the one browsing route
 * without a secure context (a raw IP, where {@code navigator.credentials} does not exist). Null
 * here means "no password factor" and never "empty password" — a blank one is refused on the way
 * in, which is also the only password rule there is.
 *
 * <p>Users are <b>per-installation</b>: these rows survive deploys and restarts like every other
 * idp row, and are never shared or migrated between installations of the platform. That is what
 * makes a passkey's rp-id binding to one host a decision rather than a migration problem.
 */
@Entity
@Table(name = "idp_user")
public class IdpUser extends PanacheEntityBase {

  /** The {@code X-Qits-User-Id} the edge injects once sessions are gated, and the row's identity. */
  @Id
  @Column(name = "id")
  public UUID id;

  /**
   * The name the account is known by — the login name, the key a WebAuthn credential record carries
   * inside the extension, and the {@code X-Qits-User} downstream services already read. Unique.
   */
  @Column(name = "username", nullable = false, length = 128, unique = true)
  public String username;

  /**
   * The password, one-way, {@code bcrypt:}-prefixed — see {@link
   * eu.wohlben.qits.idp.control.PasswordHash}. Null while the account has no password factor.
   */
  @Column(name = "password_hash", length = 255)
  public String passwordHash;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;
}
