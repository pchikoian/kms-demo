package com.demo.s3proxy;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import com.google.common.base.Strings;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.ContentMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ForwardingBlobStore} that applies Vault Transit envelope encryption
 * transparently on every object stored in the underlying BlobStore.
 *
 * <p>Follows the same middleware pattern as gaul/s3proxy's built-in
 * {@code EncryptedBlobStore}: activated by a properties flag and wired in the
 * same decorator chain.
 *
 * <h2>Envelope encryption (DEK/KEK)</h2>
 * <ol>
 *   <li><b>PUT</b>: generate a fresh AES-256 DEK via Vault
 *       {@code transit/datakey/plaintext}, encrypt the payload with AES-256-GCM,
 *       store the Vault-wrapped DEK in S3 user metadata.</li>
 *   <li><b>GET</b>: read the wrapped DEK from metadata, unwrap via Vault
 *       {@code transit/decrypt}, decrypt the payload with AES-256-GCM.</li>
 *   <li><b>Everything else</b>: delegated unchanged via
 *       {@link ForwardingBlobStore}.</li>
 * </ol>
 *
 * <h2>Configuration properties</h2>
 * <pre>
 *   s3proxy.vault-transit-blobstore        true to enable
 *   s3proxy.vault-transit-blobstore.addr   Vault HTTP address
 *   s3proxy.vault-transit-blobstore.token  Vault token
 *   s3proxy.vault-transit-blobstore.key    Transit key name
 * </pre>
 */
public final class VaultTransitEncryptingBlobStore extends ForwardingBlobStore {

    private static final Logger logger =
            LoggerFactory.getLogger(VaultTransitEncryptingBlobStore.class);

    /** S3 user-metadata key for the Vault-wrapped DEK. */
    static final String META_DEK          = "encrypted-dek";
    /** S3 user-metadata key to round-trip the original content-type. */
    static final String META_CONTENT_TYPE = "original-content-type";

    private final VaultTransitClient vault;

    /** Package-private: allows unit tests to inject a mock VaultTransitClient. */
    VaultTransitEncryptingBlobStore(BlobStore blobStore,
            VaultTransitClient vault) {
        super(blobStore);
        this.vault = vault;
    }

    private VaultTransitEncryptingBlobStore(BlobStore blobStore,
            Properties properties) {
        super(blobStore);

        String addr = properties.getProperty(
                VaultTransitConstants.PROPERTY_VAULT_ADDR);
        checkArgument(!Strings.isNullOrEmpty(addr),
                "Vault address not set: " + VaultTransitConstants.PROPERTY_VAULT_ADDR);

        String token = properties.getProperty(
                VaultTransitConstants.PROPERTY_VAULT_TOKEN);
        checkArgument(!Strings.isNullOrEmpty(token),
                "Vault token not set: " + VaultTransitConstants.PROPERTY_VAULT_TOKEN);

        String key = properties.getProperty(
                VaultTransitConstants.PROPERTY_VAULT_KEY);
        checkArgument(!Strings.isNullOrEmpty(key),
                "Vault transit key not set: " + VaultTransitConstants.PROPERTY_VAULT_KEY);

        this.vault = new VaultTransitClient(addr, token, key);
    }

    /**
     * Creates a new {@code VaultTransitEncryptingBlobStore} from properties.
     * Mirrors the factory convention used by gaul/s3proxy middleware classes.
     */
    public static BlobStore newVaultTransitEncryptingBlobStore(
            BlobStore blobStore, Properties properties) throws IOException {
        return new VaultTransitEncryptingBlobStore(blobStore, properties);
    }

    // ── PUT ──────────────────────────────────────────────────────────────────

    @Override
    public String putBlob(String container, Blob blob) {
        return encryptAndPut(container, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        return encryptAndPut(container, blob, options);
    }

    private String encryptAndPut(String container, Blob blob,
            PutOptions options) {
        BlobMetadata meta      = blob.getMetadata();
        ContentMetadata cMeta  = meta.getContentMetadata();
        String name            = meta.getName();

        try {
            byte[] plaintext;
            try (InputStream in = blob.getPayload().openStream()) {
                plaintext = in.readAllBytes();
            }

            VaultTransitClient.DataKey dk = vault.generateDataKey();
            byte[] ciphertext = AesGcm.encrypt(dk.plaintext(), plaintext);

            Map<String, String> userMeta = new HashMap<>(meta.getUserMetadata());
            userMeta.put(META_DEK, dk.ciphertext());
            String origCt = cMeta.getContentType();
            if (!Strings.isNullOrEmpty(origCt)) {
                userMeta.put(META_CONTENT_TYPE, origCt);
            }

            Blob encrypted = blobBuilder(container)
                    .name(name)
                    .type(meta.getType())
                    .tier(meta.getTier())
                    .userMetadata(userMeta)
                    .payload(ciphertext)
                    .contentLength(ciphertext.length)
                    .contentType("application/octet-stream")
                    .build();

            logger.info("PUT {}/{} plain={}B cipher={}B",
                    container, name, plaintext.length, ciphertext.length);

            return delegate().putBlob(container, encrypted, options);

        } catch (Exception e) {
            throw new RuntimeException(
                    "Vault encryption failed for " + container + "/" + name, e);
        }
    }

    // ── GET ──────────────────────────────────────────────────────────────────

    @Override
    public Blob getBlob(String container, String name) {
        return decryptBlob(container, name,
                delegate().getBlob(container, name));
    }

    @Override
    public Blob getBlob(String container, String name, GetOptions options) {
        // s3proxy applies the range after we return plaintext.
        return decryptBlob(container, name,
                delegate().getBlob(container, name));
    }

    private Blob decryptBlob(String container, String name, Blob blob) {
        if (blob == null) {
            return null;
        }

        BlobMetadata blobMeta = blob.getMetadata();
        Map<String, String> userMeta = blobMeta.getUserMetadata();
        String encDek = userMeta.get(META_DEK);

        if (encDek == null) {
            logger.warn("GET {}/{} — no {} metadata; returning raw object",
                    container, name, META_DEK);
            return blob;
        }

        try {
            byte[] dek = vault.decryptDataKey(encDek);

            byte[] ciphertext;
            try (InputStream in = blob.getPayload().openStream()) {
                ciphertext = in.readAllBytes();
            }

            byte[] plaintext = AesGcm.decrypt(dek, ciphertext);

            String contentType = userMeta.getOrDefault(
                    META_CONTENT_TYPE, "application/octet-stream");

            Map<String, String> outMeta = new HashMap<>(userMeta);
            outMeta.remove(META_DEK);
            outMeta.remove(META_CONTENT_TYPE);

            ContentMetadata cMeta = blobMeta.getContentMetadata();

            Blob decrypted = blobBuilder(container)
                    .name(name)
                    .type(blobMeta.getType())
                    .tier(blobMeta.getTier())
                    .userMetadata(outMeta)
                    .payload(plaintext)
                    .cacheControl(cMeta.getCacheControl())
                    .contentDisposition(cMeta.getContentDisposition())
                    .contentEncoding(cMeta.getContentEncoding())
                    .contentLanguage(cMeta.getContentLanguage())
                    .contentLength(plaintext.length)
                    .contentType(contentType)
                    .build();

            // Preserve mutable metadata so s3proxy can build a correct response.
            decrypted.getMetadata().setUri(blobMeta.getUri());
            decrypted.getMetadata().setETag(blobMeta.getETag());
            decrypted.getMetadata().setLastModified(blobMeta.getLastModified());
            decrypted.getMetadata().setPublicUri(blobMeta.getPublicUri());
            decrypted.getMetadata().setContainer(container);

            logger.info("GET {}/{} cipher={}B plain={}B",
                    container, name, ciphertext.length, plaintext.length);

            return decrypted;

        } catch (Exception e) {
            throw new RuntimeException(
                    "Vault decryption failed for " + container + "/" + name, e);
        }
    }
}
