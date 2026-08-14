package eu.wohlben.qits.idp.control;

import io.quarkus.elytron.security.common.BcryptUtil;

/**
 * A user's password, and the two operations anything here needs: hash one, and check one.
 *
 * <p><b>Why bcrypt when the client secrets next door are a plain SHA-256.</b> {@link ClientSecret}
 * argues, correctly, that a 256-bit value out of {@link java.security.SecureRandom} has no guessing
 * to slow down — so a password hash there would only put a cost on the token path, which is the
 * platform's whole call graph. A <b>human-chosen</b> password is exactly the case that argument
 * does not cover: it is guessable by construction, and the work factor is the only thing standing
 * between a leaked database dump and every account in it. So the two schemes live side by side,
 * which is what the scheme prefix in the stored value was put there for.
 *
 * <p><b>The only password rule is that it is not empty.</b> No length floor, no character classes,
 * no expiry — deliberately, and it is a decision rather than an omission (user-authentication-plan.md,
 * 2026-08-14). Composition rules push people towards predictable passwords and towards writing them
 * down, and this account is passwordless by default anyway: the password exists for automated tests
 * and for the one browsing route with no secure context, where {@code navigator.credentials} does
 * not exist at all.
 *
 * <p>The work factor is {@code BcryptUtil}'s own default (10 rounds). It is not configurable here:
 * a login is a handful of requests a day, so the number that matters is the one an attacker with
 * the dump pays, and picking it per deployment would only mean some deployment picks a low one.
 */
public final class PasswordHash {

  /** Names the scheme in the stored value, beside {@link ClientSecret}'s {@code sha-256:}. */
  private static final String BCRYPT_PREFIX = "bcrypt:";

  private PasswordHash() {}

  /**
   * What goes in {@code idp_user.password_hash} for this plaintext.
   *
   * @throws IllegalArgumentException when the password is null or blank — the caller is expected to
   *     have refused that already with an answer a browser can show
   */
  public static String of(String plaintext) {
    if (plaintext == null || plaintext.isEmpty()) {
      throw new IllegalArgumentException("a password must not be empty");
    }
    return BCRYPT_PREFIX + BcryptUtil.bcryptHash(plaintext);
  }

  /**
   * Whether {@code candidate} is the password behind {@code stored}.
   *
   * <p>False for a null or blank stored value, which is how an account with <b>no</b> password
   * factor refuses a password login: the column is null until someone sets one, and null must never
   * read as "any password will do". False for an unknown scheme prefix too — a value this class did
   * not write is not a password it can check.
   */
  public static boolean matches(String stored, String candidate) {
    if (stored == null || candidate == null || candidate.isEmpty()) {
      return false;
    }
    if (!stored.startsWith(BCRYPT_PREFIX)) {
      return false;
    }
    return BcryptUtil.matches(candidate, stored.substring(BCRYPT_PREFIX.length()));
  }
}
