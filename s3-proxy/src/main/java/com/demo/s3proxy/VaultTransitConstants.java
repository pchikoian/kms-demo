package com.demo.s3proxy;

/**
 * Property keys for the Vault Transit envelope-encryption middleware.
 *
 * <p>Follows the same naming convention as
 * {@code org.gaul.s3proxy.S3ProxyConstants}.
 */
public final class VaultTransitConstants {

    /** Set to {@code true} to wrap the BlobStore with Vault Transit encryption. */
    public static final String PROPERTY_VAULT_TRANSIT_BLOBSTORE =
            "s3proxy.vault-transit-blobstore";

    /** Vault server address, e.g. {@code http://vault:8200}. */
    public static final String PROPERTY_VAULT_ADDR =
            "s3proxy.vault-transit-blobstore.addr";

    /** Vault token used to authenticate Transit API calls. */
    public static final String PROPERTY_VAULT_TOKEN =
            "s3proxy.vault-transit-blobstore.token";

    /** Name of the Transit key (KEK) used to wrap/unwrap DEKs. */
    public static final String PROPERTY_VAULT_KEY =
            "s3proxy.vault-transit-blobstore.key";

    private VaultTransitConstants() {}
}
