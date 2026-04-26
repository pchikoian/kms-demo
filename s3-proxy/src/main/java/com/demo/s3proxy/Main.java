package com.demo.s3proxy;

import org.gaul.s3proxy.AuthenticationType;
import org.gaul.s3proxy.S3Proxy;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Entry point. Wires together:
 * <ol>
 *   <li>jclouds S3 BlobStoreContext → MinIO backend</li>
 *   <li>{@link VaultTransitEncryptingBlobStore} middleware (following gaul's
 *       decorator pattern, activated via properties)</li>
 *   <li>gaul/s3proxy server on the configured listen address</li>
 * </ol>
 *
 * <h2>Configuration (environment variables)</h2>
 * <pre>
 *   S3PROXY_LISTEN           listen address               default :8080
 *   S3PROXY_VAULT_ADDR       Vault HTTP address           default http://vault:8200
 *   S3PROXY_VAULT_TOKEN      Vault token                  (or /shared/s3proxy-token)
 *   S3PROXY_VAULT_KEY        Transit key name             default demo-kek
 *   S3PROXY_MINIO_ENDPOINT   MinIO HTTP endpoint          default http://minio:9000
 *   S3PROXY_MINIO_ACCESS_KEY MinIO access key             default minioadmin
 *   S3PROXY_MINIO_SECRET_KEY MinIO secret key             default minioadmin
 *   S3PROXY_ACCESS_KEY       Client-facing access key     (empty = NONE auth)
 *   S3PROXY_SECRET_KEY       Client-facing secret key
 * </pre>
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        Config cfg = Config.fromEnv();
        log.info("Starting s3-proxy (gaul/s3proxy {})",
                S3Proxy.class.getPackage().getImplementationVersion());
        log.info("  vault:  {} (key={})", cfg.vaultAddr(), cfg.vaultKey());
        log.info("  minio:  {}", cfg.minioEndpoint());
        log.info("  listen: {}", cfg.listen());

        // ── 1. MinIO BlobStore via aws-s3-sdk (jclouds s3 removed in s3proxy 3.x)
        //    The aws-s3-sdk provider auto-enables path-style for non-AWS endpoints.
        BlobStoreContext ctx = ContextBuilder.newBuilder("aws-s3-sdk")
                .credentials(cfg.minioAccessKey(), cfg.minioSecretKey())
                .endpoint(cfg.minioEndpoint())
                .buildView(BlobStoreContext.class);

        BlobStore blobStore = ctx.getBlobStore();

        // ── 2. Wrap with Vault Transit envelope encryption ───────────────────
        //    Follows gaul's parseMiddlewareProperties pattern: build a Properties
        //    object and call the static factory on the middleware class.
        var vaultProps = new Properties();
        vaultProps.setProperty(VaultTransitConstants.PROPERTY_VAULT_TRANSIT_BLOBSTORE, "true");
        vaultProps.setProperty(VaultTransitConstants.PROPERTY_VAULT_ADDR,  cfg.vaultAddr());
        vaultProps.setProperty(VaultTransitConstants.PROPERTY_VAULT_TOKEN, cfg.vaultToken());
        vaultProps.setProperty(VaultTransitConstants.PROPERTY_VAULT_KEY,   cfg.vaultKey());

        if ("true".equalsIgnoreCase(
                vaultProps.getProperty(VaultTransitConstants.PROPERTY_VAULT_TRANSIT_BLOBSTORE))) {
            log.info("  encryption: Vault Transit ({})", cfg.vaultAddr());
            blobStore = VaultTransitEncryptingBlobStore
                    .newVaultTransitEncryptingBlobStore(blobStore, vaultProps);
        }

        // ── 3. Build and start gaul/s3proxy ──────────────────────────────────
        URI endpoint = URI.create("http://0.0.0.0:" + cfg.listenPort());

        S3Proxy.Builder builder = S3Proxy.builder()
                .blobStore(blobStore)
                .endpoint(endpoint);

        if (cfg.proxyAccessKey() != null && !cfg.proxyAccessKey().isBlank()) {
            log.info("  auth:   AWS_V2_OR_V4 (identity={})", cfg.proxyAccessKey());
            builder.awsAuthentication(
                    AuthenticationType.AWS_V2_OR_V4,
                    cfg.proxyAccessKey(),
                    cfg.proxySecretKey());
        } else {
            log.info("  auth:   NONE");
            builder.awsAuthentication(AuthenticationType.NONE, "", "");
        }

        S3Proxy s3proxy = builder.build();
        s3proxy.start();
        log.info("s3-proxy ready on {}", endpoint);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                log.info("Shutting down…");
                s3proxy.stop();
                ctx.close();
            } catch (Exception e) {
                log.warn("Error during shutdown", e);
            }
        }));

        Thread.currentThread().join();
    }

    // ── Config ────────────────────────────────────────────────────────────────

    record Config(
            String listen,
            String vaultAddr,
            String vaultToken,
            String vaultKey,
            String minioEndpoint,
            String minioAccessKey,
            String minioSecretKey,
            String proxyAccessKey,
            String proxySecretKey
    ) {
        static Config fromEnv() throws Exception {
            String token = env("S3PROXY_VAULT_TOKEN", "");
            if (token.isBlank()) {
                Path tokenFile = Path.of("/shared/s3proxy-token");
                if (Files.exists(tokenFile)) {
                    token = Files.readString(tokenFile).strip();
                }
            }
            if (token.isBlank()) {
                throw new IllegalStateException(
                        "No Vault token: set S3PROXY_VAULT_TOKEN or write to /shared/s3proxy-token");
            }
            return new Config(
                    env("S3PROXY_LISTEN",            ":8080"),
                    env("S3PROXY_VAULT_ADDR",         "http://vault:8200"),
                    token,
                    env("S3PROXY_VAULT_KEY",          "demo-kek"),
                    env("S3PROXY_MINIO_ENDPOINT",     "http://minio:9000"),
                    env("S3PROXY_MINIO_ACCESS_KEY",   "minioadmin"),
                    env("S3PROXY_MINIO_SECRET_KEY",   "minioadmin"),
                    env("S3PROXY_ACCESS_KEY",         ""),
                    env("S3PROXY_SECRET_KEY",         "")
            );
        }

        int listenPort() {
            String s = listen.startsWith(":") ? listen.substring(1) : listen;
            return Integer.parseInt(s.contains(":") ? s.split(":")[1] : s);
        }
    }

    private static String env(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.isBlank()) ? v : fallback;
    }
}
