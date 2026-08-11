package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpSigningKey;
import eu.wohlben.qits.idp.entity.IdpSigningKeyStatus;
import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * The signing keys, generated once and read from the database ever after.
 *
 * <p>This is the whole of "validation survives a restart": the first start that finds no {@code
 * ACTIVE} row generates a keypair and persists it; every start after that loads the same one, so
 * the {@code kid} in a token issued yesterday still resolves against today's JWKS.
 *
 * <p>Rotation needs no code here. Insert a second {@code ACTIVE} row and retire the first, and
 * {@link #reload()} picks the new signer up while the old key keeps being published — which is why
 * the reload is public API rather than a test hook.
 */
@ApplicationScoped
public class SigningKeys {

  private static final Logger LOG = Logger.getLogger(SigningKeys.class);

  /** The only JWS algorithm this service signs with, and the {@code alg} of every published JWK. */
  public static final String ALGORITHM = "RS256";

  /**
   * One usable key: the {@code kid} its tokens carry, the private half that signs, and the public
   * half the JWKS publishes.
   */
  public record SigningKey(
      String kid,
      String algorithm,
      RSAPrivateKey privateKey,
      RSAPublicKey publicKey,
      boolean active) {}

  /** What one load produced: the signer, and everything to publish (the signer included). */
  public record KeySet(SigningKey signing, List<SigningKey> published) {}

  @Inject IdpSigningKeyRepository repository;

  @ConfigProperty(name = "qits.idp.signing-key-bits")
  int keyBits;

  private volatile KeySet cached;

  /**
   * Generate-or-load at boot, so a first start fails loudly on an unwritable database rather than
   * on the first token request.
   */
  void onStart(@Observes StartupEvent event) {
    KeySet keys = reload();
    LOG.infof(
        "idp signing key %s active, %d key(s) published", keys.signing().kid(), keys.published().size());
  }

  /** The key new tokens are signed with. */
  public SigningKey signing() {
    return keys().signing();
  }

  /** Every key the JWKS publishes — the signer plus any retired key whose tokens may still live. */
  public List<SigningKey> published() {
    return keys().published();
  }

  /**
   * Re-read the keys from the database, generating one only if there is no active key at all.
   *
   * <p><b>Held through a postgres cutover</b> ({@link DbRetry}, connection-class failures only, 15
   * seconds). Both callers are ones a lost connection would answer badly: the boot load fails the
   * process, and a rotation would report a database that is coming back as a rotation that did not
   * happen.
   *
   * <p>The retry is <b>outside</b> the monitor, which is why {@link #loadOnce()} carries the
   * {@code synchronized} and this method no longer does. Each attempt takes the lock and releases
   * it, so nothing sleeps while holding it — and the guard the lock exists for is untouched, since
   * one load still finishes and commits before the next begins. What is no longer serialized is the
   * assignment below: two concurrent reloads may write their key sets in either order, and both are
   * complete sets read moments apart. The reads never take the lock at all — {@link #signing()} and
   * {@link #published()} go through the volatile field.
   */
  public KeySet reload() {
    KeySet next = DbRetry.call("idp signing key load", this::loadOnce);
    cached = next;
    return next;
  }

  /**
   * One load attempt, in its own transaction. Synchronized so two callers on a cold cache cannot
   * both generate; it waits for nothing, so the lock is held for one round trip.
   */
  private synchronized KeySet loadOnce() {
    return QuarkusTransaction.requiringNew().call(this::loadOrCreate);
  }

  private KeySet keys() {
    KeySet local = cached;
    return local != null ? local : reload();
  }

  /** Runs inside the transaction: the rows are turned into keys before the session closes. */
  private KeySet loadOrCreate() {
    List<IdpSigningKey> rows = repository.listNewestFirst();
    if (rows.stream().noneMatch(row -> row.status == IdpSigningKeyStatus.ACTIVE)) {
      repository.persist(generate());
      repository.flush();
      rows = repository.listNewestFirst();
    }
    List<SigningKey> published = rows.stream().map(SigningKeys::toKey).toList();
    SigningKey signing =
        published.stream()
            .filter(SigningKey::active)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no active signing key after load"));
    return new KeySet(signing, published);
  }

  private IdpSigningKey generate() {
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(keyBits);
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("cannot generate an RSA signing key", e);
    }
    IdpSigningKey row = new IdpSigningKey();
    row.kid = randomKid();
    row.algorithm = ALGORITHM;
    row.status = IdpSigningKeyStatus.ACTIVE;
    row.privateKeyPem = Pem.wrap("PRIVATE KEY", pair.getPrivate().getEncoded());
    row.publicKeyPem = Pem.wrap("PUBLIC KEY", pair.getPublic().getEncoded());
    row.createdAt = Instant.now();
    return row;
  }

  private static SigningKey toKey(IdpSigningKey row) {
    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      RSAPrivateKey privateKey =
          (RSAPrivateKey)
              factory.generatePrivate(new PKCS8EncodedKeySpec(Pem.unwrap(row.privateKeyPem)));
      RSAPublicKey publicKey =
          (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(Pem.unwrap(row.publicKeyPem)));
      return new SigningKey(
          row.kid,
          row.algorithm,
          privateKey,
          publicKey,
          row.status == IdpSigningKeyStatus.ACTIVE);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new IllegalStateException("stored signing key " + row.kid + " is unreadable", e);
    }
  }

  /** 128 random bits, base64url. Opaque on purpose: a kid names a key and says nothing else. */
  private static String randomKid() {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
