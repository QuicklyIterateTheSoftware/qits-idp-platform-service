package eu.wohlben.qits.idp.control;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * A client's shared secret, and the one operation anything here needs from it: does a presented
 * value match.
 *
 * <p>There are two kinds and the difference is where the secret lives, not what it means.
 *
 * <ul>
 *   <li><b>Configured</b> — an environment service client's secret, read from {@code
 *       qits.idp.client.<id>.secret}. The value itself is what the process holds, because the
 *       deployment handed it over that way; there is nothing to hash it against.
 *   <li><b>Stored</b> — a commissioned client's secret, or a database service client's, held as a
 *       hash in {@code idp_client.secret_hash} or {@code idp_service_client.secret_hash}. <b>The
 *       plaintext exists once</b>, in the commission or create/rotate response, and is never
 *       written down here. A dump of the idp's database therefore mints nothing.
 * </ul>
 *
 * <p><b>A database service client during a rotation carries two hashes.</b> {@code
 * ServiceClients.rotate} keeps the previous hash live for fifteen minutes (D4 of
 * {@code service-client-identity-plan.md}), so a start-first rollback to the predecessor container
 * — still holding the old secret — is not locked out. {@link #serviceClient} is where both hashes,
 * and the environment secret during the migration overlap, are tried in one place: environment
 * value, current hash, then the previous hash while it is still live. The expiry is checked at
 * {@link #matches}, not at construction, because a resolved client can sit in a request-scoped
 * lookup for longer than an instant.
 *
 * <p>Both kinds compare with {@link MessageDigest#isEqual}, never {@code String.equals}: the
 * comparison is against a value a caller may retry freely.
 *
 * <p><b>Why a plain SHA-256 and not bcrypt/argon2.</b> Those exist to make guessing a
 * human-chosen password expensive. A commissioned or a database service client's secret is 256 bits
 * from {@link java.security.SecureRandom} and is never chosen by anyone, so there is no guessing to
 * slow down — only a cost on the token path, which is the platform's whole call graph. A one-way
 * function is what the row needs and all it needs.
 */
public final class ClientSecret {

  /** Names the scheme in the stored value, so a second one can be added without a migration. */
  private static final String SHA256_PREFIX = "sha-256:";

  /** One hash this secret accepts, and until when — null means no expiry. */
  private record Hash(String value, Instant validUntil) {
    boolean live(Instant now) {
      return validUntil == null || validUntil.isAfter(now);
    }
  }

  private final String configured;
  private final List<Hash> hashes;

  private ClientSecret(String configured, List<Hash> hashes) {
    this.configured = configured;
    this.hashes = hashes;
  }

  /**
   * An environment client's secret as the deployment set it. Null or blank makes an <b>unusable</b>
   * client — see {@link IdpClient#usable()}.
   */
  public static ClientSecret configured(String value) {
    return new ClientSecret(value, List.of());
  }

  /** A commissioned client's secret, as the row holds it. No previous hash: commissions never rotate. */
  public static ClientSecret stored(String hash) {
    return new ClientSecret(null, hash == null ? List.of() : List.of(new Hash(hash, null)));
  }

  /**
   * A service client resolved during the migration: an environment value when one is configured for
   * this id, a database current hash, and a database previous hash while it stays live — any of the
   * three authenticates.
   *
   * @param configuredValue the environment secret for this id, or null when there is no environment
   *     entry
   * @param currentHash the database row's current hash, or null when there is no database row
   * @param previousHash the row's previous hash after a rotation, or null when it never rotated or
   *     the grace has already been dropped from the row
   * @param previousValidUntil when {@code previousHash} stops being accepted; ignored when {@code
   *     previousHash} is null
   */
  public static ClientSecret serviceClient(
      String configuredValue, String currentHash, String previousHash, Instant previousValidUntil) {
    List<Hash> hashes = new ArrayList<>(2);
    if (currentHash != null && !currentHash.isBlank()) {
      hashes.add(new Hash(currentHash, null));
    }
    if (previousHash != null && !previousHash.isBlank() && previousValidUntil != null) {
      hashes.add(new Hash(previousHash, previousValidUntil));
    }
    return new ClientSecret(configuredValue, List.copyOf(hashes));
  }

  /**
   * Two secrets, either of which authenticates — the dual-source rule for a service client that
   * exists in both the environment and the database mid-migration: the environment's configured
   * value (carried by {@code first}, an environment client's own secret) or the database's hash(es)
   * (carried by {@code second}). Order does not matter; this is symmetric.
   */
  public static ClientSecret either(ClientSecret first, ClientSecret second) {
    String mergedConfigured =
        first.configured != null && !first.configured.isBlank() ? first.configured : second.configured;
    List<Hash> mergedHashes = new ArrayList<>(first.hashes.size() + second.hashes.size());
    mergedHashes.addAll(first.hashes);
    mergedHashes.addAll(second.hashes);
    return new ClientSecret(mergedConfigured, List.copyOf(mergedHashes));
  }

  /** What goes in a {@code secret_hash} column for this plaintext. */
  public static String hash(String plaintext) {
    return SHA256_PREFIX
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(sha256(plaintext.getBytes(StandardCharsets.UTF_8)));
  }

  /** Whether this secret can authenticate anything at all, right now. A blank one cannot. */
  public boolean usable() {
    if (configured != null && !configured.isBlank()) {
      return true;
    }
    Instant now = Instant.now();
    return hashes.stream().anyMatch(hash -> hash.live(now));
  }

  /** Whether {@code candidate} is this secret, by any live source. False when {@link #usable()} is false. */
  public boolean matches(String candidate) {
    if (candidate == null) {
      return false;
    }
    if (configured != null && !configured.isBlank() && equal(configured, candidate)) {
      return true;
    }
    if (hashes.isEmpty()) {
      return false;
    }
    String candidateHash = hash(candidate);
    Instant now = Instant.now();
    for (Hash hash : hashes) {
      if (hash.live(now) && equal(hash.value(), candidateHash)) {
        return true;
      }
    }
    return false;
  }

  private static boolean equal(String one, String other) {
    return MessageDigest.isEqual(
        one.getBytes(StandardCharsets.UTF_8), other.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is required of every JVM. Reachable only in a native image that lost the provider,
      // which is the class of failure IdpPackagedSurfaceIT exists to catch.
      throw new IllegalStateException("SHA-256 is unavailable in this runtime", e);
    }
  }
}
