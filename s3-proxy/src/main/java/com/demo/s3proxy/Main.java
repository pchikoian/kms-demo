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
 * Entry point.  Wires together:
 * <ol>
 *   <li>jclouds S3 BlobStoreContext → MinIO backend</li>
 *   <li>{@link VaultTransitClient} → HashiCorp Vault Transit engine</li>
 *   <li>{@link EncryptingBlobStore} wrapper</li>
 *   <li>gaul/s3proxy server on the configured listen address</li>
 * </ol>
 *
 * <h2>Configuration (environment variables)</h2>
 * <pre>
 *   S3PROXY_LISTEN           listen address          default :8080
 *   S3PROXY_VAULT_ADDR       Vault HTTP address      default http://vault:8200
 *   S3PROXY_VAULT_TOKEN      Vault token             (or read from /shared/s3proxy-token)
 *   S3PROXY_VAULT_KEY        Transit key name        default demo-kek
 *   S3PROXY_MINIO_ENDPOINT   MinIO HTTP endpoint     default http://minio:9000
 *   S3PROXY_MINIO_ACCESS_KEY MinIO access key        default minioadmin
 *   S3PROXY_MINIO_SECRET_KEY MinIO secret key        default minioadmin
 *   S3PROXY_ACCESS_KEY       Client-facing access key (empty = NONE auth)
 *   S3PROXY_SECRET_KEY       Client-facing secret key
 * </pre>
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        Config cfg = Config.fromEnv();
        log.info("Starting s3-proxy");
        log.info("  vault:  {} (key={})", cfg.vaultAddr, cfg.vaultKey);
        log.info("  minio:  {}", cfg.minioEndpoint);
        log.info("  listen: {}", cfg.listen);

        // ── 1. MinIO BlobStore via jclouds S3 API ────────────────────────────
        Properties overrides = new Properties();
        // Path-style addressing required for MinIO (no virtual-host buckets)
        overrides.setProperty("jclouds.s3.virtual-host-buckets", "false");

        BlobStoreContext ctx = ContextBuilder.newBuilder("s3")
                .credentials(cfg.minioAccessKey, cfg.minioSecretKey)
                .endpoint(cfg.minioEndpoint)
                .overrides(overrides)
                .buildView(BlobStoreContext.class);

        BlobStore minioBlobStore = ctx.getBlobStore();

        // ── 2. Vault Transit client ───────────────────────────────────────────
        VaultTransitClient vault = new VaultTransitClient(
                cfg.vaultAddr, cfg.vaultToken, cfg.vaultKey);

        // ── 3. Wrap MinIO BlobStore with transparent encryption ───────────────
        EncryptingBlobStore encryptingBlobStore =
                new EncryptingBlobStore(minioBlobStore, vault);

        // ── 4. Build and start gaul/s3proxy ───────────────────────────────────
        URI endpoint = URI.create("http://0.0.0.0:" + cfg.listenPort());

        S3Proxy.Builder builder = S3Proxy.builder()
                .blobStore(encryptingBlobStore)
                .endpoint(endpoint);

        if (cfg.proxyAccessKey != null && !cfg.proxyAccessKey.isBlank()) {
            log.info("  auth:   AWS_V2_OR_V4 (access key: {})", cfg.proxyAccessKey);
            builder.awsAuthentication(
                    AuthenticationType.AWS_V2_OR_V4,
                    cfg.proxyAccessKey,
                    cfg.proxySecretKey);
        } else {
            log.info("  auth:   NONE (S3PROXY_ACCESS_KEY not set)");
            builder.awsAuthentication(AuthenticationType.NONE, "", "");
        }

        S3Proxy s3proxy = builder.build();
        s3proxy.start();

        log.info("s3-proxy ready on {}", endpoint);

        // Block until killed
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

        /** Extracts the numeric port from a listen value like ":8080". */
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
