package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One commissioned credential: a client that exists because a service provisioned a dynamic context
 * and asked for it, and that stops existing when the row is deleted.
 *
 * <p><b>The row is the whole lifetime.</b> There is no lease and no expiry column — a commissioned
 * credential lives exactly as long as the context it was minted for, and the owner that
 * commissioned it is the one that says when that ended. Deleting the row makes the client unable to
 * mint immediately; tokens it already minted live out their {@code exp}, which is the accepted cost
 * recorded on {@code qits.idp.token-ttl-seconds}.
 *
 * <p>{@link #owner}, {@link #contextKind} and {@link #contextId} are the triple every commission
 * carries from day one. The owner is who may decommission and who may list; the two context fields
 * are what a reconcile compares against its own live contexts, and what per-context permission
 * scoping will attach to when it arrives.
 */
@Entity
@Table(name = "idp_client")
public class IdpDynamicClient extends PanacheEntityBase {

  /** The {@code sub} of every token this credential mints, and the row's identity. */
  @Id
  @Column(name = "client_id", length = 128)
  public String clientId;

  /**
   * The secret, one-way. The plaintext left this process once, in the commission response, and was
   * never written here — see {@link eu.wohlben.qits.idp.control.ClientSecret}.
   */
  @Column(name = "secret_hash", nullable = false, length = 255)
  public String secretHash;

  /**
   * The client that commissioned this one. Only that client — or this one itself — may decommission
   * it, and this credential's audiences and claims are read from the owner's record at mint time.
   */
  @Column(name = "owner", nullable = false, length = 128)
  public String owner;

  /** What kind of context this credential belongs to: {@code ci-run}, {@code workspace}, … */
  @Column(name = "context_kind", nullable = false, length = 32)
  public String contextKind;

  /** Which context of that kind, in the owner's own spelling. Opaque here. */
  @Column(name = "context_id", nullable = false, length = 256)
  public String contextId;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;
}
