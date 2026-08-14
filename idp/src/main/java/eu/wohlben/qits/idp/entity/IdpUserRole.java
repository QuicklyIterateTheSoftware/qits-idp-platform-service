package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One role granted to one account.
 *
 * <p><b>The strings are namespaced and opaque here.</b> The shape is {@code $app:$resource:$role}
 * and the middle segment is simply omitted until something needs it, so the two rows a bootstrap
 * registration writes read {@code qits-platform:admin} and {@code qits:admin}. The idp stores them
 * and interprets none of them: what a role permits is a later plan, and until it lands the roles
 * travel to the edge, into {@code X-Qits-Roles}, and are enforced by nobody.
 *
 * <p><b>The pair is the primary key</b>, which is what makes granting a role twice a no-op at the
 * store rather than a check somewhere in code.
 */
@Entity
@Table(name = "idp_user_role")
@IdClass(IdpUserRole.Key.class)
public class IdpUserRole extends PanacheEntityBase {

  @Id
  @Column(name = "user_id")
  public UUID userId;

  @Id
  @Column(name = "role", length = 128)
  public String role;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /**
   * The composite key, as JPA needs it spelled: a class with a no-argument constructor, fields
   * matching the {@code @Id} members by name, and value equality. A record cannot serve — {@code
   * @IdClass} requires the no-argument constructor a record does not have.
   */
  public static class Key implements Serializable {

    public UUID userId;
    public String role;

    public Key() {}

    public Key(UUID userId, String role) {
      this.userId = userId;
      this.role = role;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof Key key)) {
        return false;
      }
      return Objects.equals(userId, key.userId) && Objects.equals(role, key.role);
    }

    @Override
    public int hashCode() {
      return Objects.hash(userId, role);
    }
  }
}
