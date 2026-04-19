package com.demo.s3proxy;

import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link ForwardingBlobStore} that transparently applies envelope encryption
 * on every object stored in the underlying (MinIO) BlobStore.
 *
 * <h2>PUT path</h2>
 * <ol>
 *   <li>Read plaintext blob payload into memory.</li>
 *   <li>Call Vault {@code transit/datakey/plaintext} to obtain a fresh AES-256 DEK.</li>
 *   <li>Encrypt payload with AES-256-GCM (nonce prepended to ciphertext).</li>
 *   <li>Store ciphertext as the new payload; attach the Vault-encrypted DEK and
 *       original content-type as S3 user metadata.</li>
 *   <li>Delegate the modified blob to the underlying BlobStore.</li>
 * </ol>
 *
 * <h2>GET path</h2>
 * <ol>
 *   <li>Fetch blob (ciphertext + metadata) from underlying BlobStore.</li>
 *   <li>Read {@code encrypted-dek} from user metadata.</li>
 *   <li>Unwrap the DEK via Vault {@code transit/decrypt}.</li>
 *   <li>Decrypt ciphertext with AES-256-GCM.</li>
 *   <li>Return a new Blob with the plaintext payload and restored content-type.</li>
 * </ol>
 *
 * <h2>Everything else</h2>
 * All other operations (list, delete, copy, multipart initiation, ACLs, …) are
 * delegated unmodified to the underlying BlobStore via {@link ForwardingBlobStore}.
 *
 * <h2>Multipart uploads</h2>
 * Large objects uploaded via the S3 multipart API are assembled by s3proxy before
 * calling {@link #putBlob}, so single-blob encryption handles them transparently
 * for most clients. For true streaming multipart encryption (each part encrypted
 * independently) see the {@code multipart-encrypt} branch TODO.
 *
 * <h2>Range requests</h2>
 * Range GET requests always decrypt the full ciphertext first, then the range is
 * applied by s3proxy. For very large objects with frequent small range reads,
 * consider AES-CTR mode to enable random-access decryption.
 */
final class EncryptingBlobStore extends ForwardingBlobStore {

    private static final Logger log = LoggerFactory.getLogger(EncryptingBlobStore.class);

    /** S3 user-metadata key (without x-amz-meta- prefix) for the Vault-encrypted DEK. */
    static final String META_DEK          = "encrypted-dek";
    /** S3 user-metadata key used to round-trip the original content-type through encryption. */
    static final String META_CONTENT_TYPE = "original-content-type";

    private final BlobStore delegate;
    private final VaultTransitClient vault;

    EncryptingBlobStore(BlobStore delegate, VaultTransitClient vault) {
        super(delegate);
        this.delegate = delegate;
        this.vault    = vault;
    }

    // -------------------------------------------------------------------------
    // PUT
    // -------------------------------------------------------------------------

    @Override
    public String putBlob(String container, Blob blob) {
        return encryptAndPut(container, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        return encryptAndPut(container, blob, options);
    }

    private String encryptAndPut(String container, Blob blob, PutOptions options) {
        String name = blob.getMetadata().getName();
        try {
            // 1. Read plaintext
            byte[] plaintext;
            try (InputStream in = blob.getPayload().openStream()) {
                plaintext = in.readAllBytes();
            }

            // 2. Generate fresh DEK from Vault
            VaultTransitClient.DataKey dataKey = vault.generateDataKey();

            // 3. Encrypt with AES-256-GCM
            byte[] ciphertext = AesGcm.encrypt(dataKey.plaintext(), plaintext);

            // 4. Build metadata — preserve original content-type so GET can restore it
            String origCt = blob.getMetadata().getContentMetadata().getContentType();
            Map<String, String> meta = new HashMap<>(blob.getMetadata().getUserMetadata());
            meta.put(META_DEK, dataKey.ciphertext());
            if (origCt != null && !origCt.isBlank()) {
                meta.put(META_CONTENT_TYPE, origCt);
            }

            // 5. Build encrypted blob
            Blob encrypted = blobBuilder(name)
                    .payload(ciphertext)
                    .contentLength(ciphertext.length)
                    .contentType("application/octet-stream")
                    .userMetadata(meta)
                    .build();

            log.info("PUT {}/{} plaintext={}B ciphertext={}B", container, name,
                     plaintext.length, ciphertext.length);

            return delegate.putBlob(container, encrypted, options);

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed for " + container + "/" + name, e);
        }
    }

    // -------------------------------------------------------------------------
    // GET
    // -------------------------------------------------------------------------

    @Override
    public Blob getBlob(String container, String name) {
        return decryptBlob(container, name, delegate.getBlob(container, name));
    }

    @Override
    public Blob getBlob(String container, String name, GetOptions options) {
        // s3proxy applies the range to the returned plaintext blob, so we always
        // decrypt the full object here. See class-level javadoc for the trade-off.
        return decryptBlob(container, name, delegate.getBlob(container, name, options));
    }

    private Blob decryptBlob(String container, String name, Blob blob) {
        if (blob == null) {
            return null;
        }

        Map<String, String> meta = blob.getMetadata().getUserMetadata();
        String encryptedDek = meta.get(META_DEK);

        if (encryptedDek == null) {
            // Object was not written through this proxy — return as-is.
            log.warn("GET {}/{} — no {} metadata; returning raw object", container, name, META_DEK);
            return blob;
        }

        try {
            // 1. Unwrap DEK
            byte[] dek = vault.decryptDataKey(encryptedDek);

            // 2. Read ciphertext
            byte[] ciphertext;
            try (InputStream in = blob.getPayload().openStream()) {
                ciphertext = in.readAllBytes();
            }

            // 3. Decrypt
            byte[] plaintext = AesGcm.decrypt(dek, ciphertext);

            // 4. Restore content-type and strip internal metadata keys from response
            String contentType = meta.getOrDefault(META_CONTENT_TYPE, "application/octet-stream");
            Map<String, String> userMeta = new HashMap<>(meta);
            userMeta.remove(META_DEK);
            userMeta.remove(META_CONTENT_TYPE);

            log.info("GET {}/{} ciphertext={}B plaintext={}B", container, name,
                     ciphertext.length, plaintext.length);

            return blobBuilder(name)
                    .payload(plaintext)
                    .contentLength(plaintext.length)
                    .contentType(contentType)
                    .userMetadata(userMeta)
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed for " + container + "/" + name, e);
        }
    }
}
