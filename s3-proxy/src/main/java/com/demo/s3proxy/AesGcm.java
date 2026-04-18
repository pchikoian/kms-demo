package com.demo.s3proxy;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM envelope encryption helpers.
 *
 * <p>Wire format: {@code [12-byte nonce][GCM ciphertext + 16-byte tag]}
 * The nonce is prepended to the ciphertext so it travels with the object and
 * does not need to be stored separately.
 */
final class AesGcm {

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS   = 128;
    private static final String ALGO    = "AES/GCM/NoPadding";

    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcm() {}

    /**
     * Encrypts {@code plaintext} with {@code dek} (must be 32 bytes for AES-256).
     *
     * @return {@code nonce || ciphertext+tag}
     */
    static byte[] encrypt(byte[] dek, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, toKey(dek), new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ciphertextAndTag = cipher.doFinal(plaintext);

        // Prepend nonce
        byte[] out = new byte[NONCE_BYTES + ciphertextAndTag.length];
        System.arraycopy(nonce,           0, out, 0,           NONCE_BYTES);
        System.arraycopy(ciphertextAndTag, 0, out, NONCE_BYTES, ciphertextAndTag.length);
        return out;
    }

    /**
     * Decrypts a blob produced by {@link #encrypt}.
     *
     * @return plaintext bytes
     * @throws Exception if the key is wrong or the data is corrupted/tampered
     */
    static byte[] decrypt(byte[] dek, byte[] ciphertext) throws Exception {
        if (ciphertext.length <= NONCE_BYTES) {
            throw new IllegalArgumentException(
                    "Ciphertext too short: " + ciphertext.length + " bytes");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(ciphertext, 0, nonce, 0, NONCE_BYTES);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, toKey(dek), new GCMParameterSpec(TAG_BITS, nonce));
        return cipher.doFinal(ciphertext, NONCE_BYTES, ciphertext.length - NONCE_BYTES);
    }

    private static SecretKey toKey(byte[] dek) {
        if (dek.length != 32) {
            throw new IllegalArgumentException(
                    "DEK must be 32 bytes for AES-256, got " + dek.length);
        }
        return new SecretKeySpec(dek, "AES");
    }
}
