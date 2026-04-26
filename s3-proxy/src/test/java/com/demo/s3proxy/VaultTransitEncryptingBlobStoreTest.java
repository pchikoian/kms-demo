package com.demo.s3proxy;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VaultTransitEncryptingBlobStoreTest {

    private static final String BUCKET = "test-bucket";

    private BlobStoreContext ctx;
    private BlobStore underlying;
    private VaultTransitClient vaultMock;
    private VaultTransitEncryptingBlobStore store;

    @BeforeEach
    void setUp() {
        ctx = ContextBuilder.newBuilder("transient")
                .credentials("id", "secret")
                .buildView(BlobStoreContext.class);
        underlying = ctx.getBlobStore();
        underlying.createContainerInLocation(null, BUCKET);

        vaultMock = mock(VaultTransitClient.class);
        store = new VaultTransitEncryptingBlobStore(underlying, vaultMock);
    }

    @AfterEach
    void tearDown() {
        ctx.close();
    }

    // -------------------------------------------------------------------------
    // PUT / GET round-trip
    // -------------------------------------------------------------------------

    @Test
    void putAndGet_roundTrip() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);
        when(vaultMock.decryptDataKey(dk.ciphertext())).thenReturn(dk.plaintext());

        byte[] original = "hello envelope encryption".getBytes();

        Blob put = store.blobBuilder("mykey")
                .payload(original).contentLength(original.length)
                .contentType("text/plain")
                .build();
        store.putBlob(BUCKET, put);

        Blob got = store.getBlob(BUCKET, "mykey");
        assertNotNull(got);
        assertArrayEquals(original, readAll(got));
    }

    @Test
    void contentType_restoredOnGet() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);
        when(vaultMock.decryptDataKey(dk.ciphertext())).thenReturn(dk.plaintext());

        byte[] data = "{}".getBytes();
        Blob put = store.blobBuilder("ct-test")
                .payload(data).contentLength(data.length)
                .contentType("application/json")
                .build();
        store.putBlob(BUCKET, put);

        Blob got = store.getBlob(BUCKET, "ct-test");
        assertEquals("application/json",
                got.getMetadata().getContentMetadata().getContentType());
    }

    // -------------------------------------------------------------------------
    // Verify backend stores ciphertext
    // -------------------------------------------------------------------------

    @Test
    void backendStoresCiphertext_notPlaintext() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);

        byte[] original = "secret payload".getBytes();
        Blob put = store.blobBuilder("secret-object")
                .payload(original).contentLength(original.length)
                .build();
        store.putBlob(BUCKET, put);

        byte[] raw = readAll(underlying.getBlob(BUCKET, "secret-object"));
        assertFalse(Arrays.equals(original, raw),
                "MinIO backend must store ciphertext, not plaintext");
    }

    @Test
    void encryptedDek_storedInObjectMetadata() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);

        Blob put = store.blobBuilder("meta-test")
                .payload(new byte[]{1, 2, 3}).contentLength(3)
                .build();
        store.putBlob(BUCKET, put);

        Blob raw = underlying.getBlob(BUCKET, "meta-test");
        assertEquals(dk.ciphertext(),
                raw.getMetadata().getUserMetadata().get(VaultTransitEncryptingBlobStore.META_DEK));
    }

    // -------------------------------------------------------------------------
    // Metadata hygiene
    // -------------------------------------------------------------------------

    @Test
    void internalMetadataKeys_strippedFromGetResponse() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);
        when(vaultMock.decryptDataKey(dk.ciphertext())).thenReturn(dk.plaintext());

        byte[] data = "data".getBytes();
        store.putBlob(BUCKET, store.blobBuilder("strip-test")
                .payload(data).contentLength(data.length)
                .contentType("application/octet-stream")
                .build());

        Blob got = store.getBlob(BUCKET, "strip-test");
        assertFalse(got.getMetadata().getUserMetadata()
                        .containsKey(VaultTransitEncryptingBlobStore.META_DEK),
                "encrypted-dek must not appear in the GET response");
        assertFalse(got.getMetadata().getUserMetadata()
                        .containsKey(VaultTransitEncryptingBlobStore.META_CONTENT_TYPE),
                "original-content-type must not appear in the GET response");
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    @Test
    void getBlob_missingDekMetadata_returnsRawBlobWithoutCallingVault() throws Exception {
        // Simulate an object written directly to MinIO, bypassing the proxy.
        Blob direct = underlying.blobBuilder("unencrypted")
                .payload("raw content".getBytes()).contentLength(11)
                .build();
        underlying.putBlob(BUCKET, direct);

        Blob got = store.getBlob(BUCKET, "unencrypted");

        assertNotNull(got);
        verifyNoInteractions(vaultMock);
    }

    @Test
    void getBlob_nonExistentKey_returnsNull() {
        assertNull(store.getBlob(BUCKET, "does-not-exist"));
    }

    @Test
    void putBlob_callsGenerateDataKeyExactlyOnce() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);

        byte[] data = "once".getBytes();
        store.putBlob(BUCKET, store.blobBuilder("once")
                .payload(data).contentLength(data.length).build());

        verify(vaultMock, times(1)).generateDataKey();
        verifyNoMoreInteractions(vaultMock);
    }

    @Test
    void getBlob_callsDecryptDataKeyExactlyOnce() throws Exception {
        VaultTransitClient.DataKey dk = freshDataKey();
        when(vaultMock.generateDataKey()).thenReturn(dk);
        when(vaultMock.decryptDataKey(dk.ciphertext())).thenReturn(dk.plaintext());

        byte[] data = "once".getBytes();
        store.putBlob(BUCKET, store.blobBuilder("once-get")
                .payload(data).contentLength(data.length).build());

        reset(vaultMock);
        when(vaultMock.decryptDataKey(dk.ciphertext())).thenReturn(dk.plaintext());

        store.getBlob(BUCKET, "once-get");

        verify(vaultMock, times(1)).decryptDataKey(dk.ciphertext());
        verifyNoMoreInteractions(vaultMock);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Returns a DataKey with a random plaintext DEK and a stub ciphertext. */
    private static VaultTransitClient.DataKey freshDataKey() {
        byte[] rawDek = new byte[32];
        new SecureRandom().nextBytes(rawDek);
        String encDek = "vault:v1:" + Base64.getEncoder().encodeToString(rawDek);
        return new VaultTransitClient.DataKey(rawDek, encDek);
    }

    private static byte[] readAll(Blob blob) throws Exception {
        try (InputStream in = blob.getPayload().openStream()) {
            return in.readAllBytes();
        }
    }
}
