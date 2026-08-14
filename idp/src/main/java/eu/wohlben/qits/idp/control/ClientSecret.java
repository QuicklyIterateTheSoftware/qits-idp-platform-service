package eu.wohlben.qits.idp.control;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * A client's shared secret, and the one operation anything here needs from it: does a presented
 * value match.
 *
 * <p>There are two kinds and the difference is where the secret lives, not what it means.
 *
 * <ul>
 *   <li><b>Configured</b> — a static service client's secret, read from {@code
 *       qits.idp.client.<id>.secret}. The value itself is what the process holds, because the
 *       deployment handed it over that way; there is nothing to hash it against.
 *   <li><b>Stored</b> — a commissioned client's secret, held as a hash in {@code
 *       idp_client.secret_hash}. <b>The plaintext exists once</b>, in the commission response, and
 *       is never written down here. A dump of the idp's database therefore mints nothing.
 * </ul>
 *
 * <p><b>Why a plain SHA-256 and not bcrypt/argon2.</b> Those exist to make guessing a
 * human-chosen password expensive. A commissioned secret is 256 bits from {@link
 * java.security.SecureRandom} and is never chosen by anyone, so there is no guessing to slow down —
 * only a cost on the token path, which is the platform's whole call graph. A one-way function is
 * what the row needs and all it needs. If a caller-chosen secret ever becomes possible, this is the
 * class that has to change, and the prefix below is what lets a second scheme land beside the first.
 *
 * <p>Both kinds compare with {@link MessageDigest#isEqual}, never {@code String.equals}: the
 * comparison is against a value a caller may retry freely.
 */
public final class ClientSecret {

  /** Names the scheme in the stored value, so a second one can be added without a migration. */
  private static final String SHA256_PREFIX = "sha-256:";

  private final String configured;
  private final String storedHash;

  private ClientSecret(String configured, String storedHash) {
    this.configured = configured;
    this.storedHash = storedHash;
  }

  /**
   * A static client's secret as the deployment set it. Null or blank makes an <b>unusable</b>
   * client — see {@link IdpClient#usable()}.
   */
  public static ClientSecret configured(String value) {
    return new ClientSecret(value, null);
  }

  /** A commissioned client's secret, as the row holds it. */
  public static ClientSecret stored(String hash) {
    return new ClientSecret(null, hash);
  }

  /** What goes in {@code idp_client.secret_hash} for this plaintext. */
  public static String hash(String plaintext) {
    return SHA256_PREFIX
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(sha256(plaintext.getBytes(StandardCharsets.UTF_8)));
  }

  /** Whether this secret can authenticate anything at all. A blank one cannot. */
  public boolean usable() {
    if (storedHash != null) {
      return !storedHash.isBlank();
    }
    return configured != null && !configured.isBlank();
  }

  /** Whether {@code candidate} is this secret. False whenever {@link #usable()} is false. */
  public boolean matches(String candidate) {
    if (!usable() || candidate == null) {
      return false;
    }
    if (storedHash != null) {
      return equal(storedHash, hash(candidate));
    }
    return equal(configured, candidate);
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
