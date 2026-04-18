package com.demo.s3proxy;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmTest {

    // A fixed all-zeros 32-byte key used throughout these unit tests.
    private static final byte[] KEY = new byte[32];

    @Test
    void roundTrip() throws Exception {
        byte[] plaintext = "hello envelope encryption".getBytes();
        byte[] ciphertext = AesGcm.encrypt(KEY, plaintext);
        assertArrayEquals(plaintext, AesGcm.decrypt(KEY, ciphertext));
    }

    @Test
    void emptyPlaintext_roundTrips() throws Exception {
        byte[] empty = new byte[0];
        assertArrayEquals(empty, AesGcm.decrypt(KEY, AesGcm.encrypt(KEY, empty)));
    }

    @Test
    void randomNonce_differentCiphertextsForSamePlaintext() throws Exception {
        byte[] plaintext = "same input".getBytes();
        byte[] c1 = AesGcm.encrypt(KEY, plaintext);
        byte[] c2 = AesGcm.encrypt(KEY, plaintext);
        assertFalse(Arrays.equals(c1, c2),
                "Each encrypt call must produce a unique ciphertext due to a random nonce");
    }

    @Test
    void wrongKey_throwsOnDecrypt() {
        byte[] wrongKey = new byte[32];
        wrongKey[0] = (byte) 0xFF;
        assertThrows(Exception.class, () -> {
            byte[] ct = AesGcm.encrypt(KEY, "secret".getBytes());
            AesGcm.decrypt(wrongKey, ct);
        });
    }

    @Test
    void tamperedCiphertext_throwsOnDecrypt() {
        assertThrows(Exception.class, () -> {
            byte[] ct = AesGcm.encrypt(KEY, "secret".getBytes());
            ct[ct.length - 1] ^= 0xFF;   // flip a byte in the GCM authentication tag
            AesGcm.decrypt(KEY, ct);
        });
    }

    @Test
    void tamperedNonce_throwsOnDecrypt() {
        assertThrows(Exception.class, () -> {
            byte[] ct = AesGcm.encrypt(KEY, "secret".getBytes());
            ct[0] ^= 0xFF;   // flip a byte inside the prepended nonce
            AesGcm.decrypt(KEY, ct);
        });
    }

    @Test
    void shortCiphertext_throwsIllegalArgumentException() {
        byte[] tooShort = new byte[5];   // shorter than the 12-byte nonce
        assertThrows(IllegalArgumentException.class, () -> AesGcm.decrypt(KEY, tooShort));
    }

    @Test
    void wrongDekLength_encrypt_throwsIllegalArgumentException() {
        byte[] badKey = new byte[16];   // AES-128 key, not AES-256
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.encrypt(badKey, "test".getBytes()));
    }

    @Test
    void wrongDekLength_decrypt_throwsIllegalArgumentException() {
        byte[] badKey = new byte[16];
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(badKey, new byte[30]));
    }

    @Test
    void ciphertextLength_isPlaintextPlusNoncePlusTag() throws Exception {
        byte[] plaintext = new byte[100];
        byte[] ciphertext = AesGcm.encrypt(KEY, plaintext);
        // 12-byte nonce + 100-byte ciphertext + 16-byte GCM tag
        assertEquals(12 + 100 + 16, ciphertext.length);
    }
}
