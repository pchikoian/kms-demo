package com.demo.s3proxy;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;

/**
 * Thin HTTP client for the Vault Transit secrets engine.
 *
 * <p>Uses {@link java.net.http.HttpClient} (Java 11+) and Gson (transitive via
 * jclouds) — no extra dependencies.
 *
 * <p>Two operations are exposed:
 * <ul>
 *   <li>{@link #generateDataKey()} — calls {@code transit/datakey/plaintext/<key>}
 *       to obtain a fresh AES-256 DEK. Returns both the plaintext DEK (for
 *       immediate use) and the Vault-encrypted DEK (safe to persist).</li>
 *   <li>{@link #decryptDataKey(String)} — calls {@code transit/decrypt/<key>}
 *       to unwrap a previously stored encrypted DEK.</li>
 * </ul>
 *
 * <p>The plaintext DEK is never logged or persisted; it exists only in heap
 * memory for the duration of a single request.
 */
final class VaultTransitClient {

    /** Carries the two DEK forms returned by the datakey endpoint. */
    record DataKey(byte[] plaintext, String ciphertext) {}

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String addr;
    private final String token;
    private final String keyName;
    private final HttpClient http;

    VaultTransitClient(String addr, String token, String keyName) {
        this.addr    = addr;
        this.token   = token;
        this.keyName = keyName;
        this.http    = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .build();
    }

    /**
     * Generates a fresh 256-bit DEK via {@code transit/datakey/plaintext/<key>}.
     */
    DataKey generateDataKey() throws Exception {
        var body = new JsonObject();
        body.addProperty("bits", 256);

        String resp = post(addr + "/v1/transit/datakey/plaintext/" + keyName,
                body.toString());
        JsonObject data = JsonParser.parseString(resp)
                .getAsJsonObject()
                .getAsJsonObject("data");

        byte[] plaintext = Base64.getDecoder().decode(
                data.get("plaintext").getAsString());
        String ciphertext = data.get("ciphertext").getAsString();
        return new DataKey(plaintext, ciphertext);
    }

    /**
     * Decrypts {@code encryptedDek} via {@code transit/decrypt/<key>}.
     *
     * @param encryptedDek the {@code vault:v1:…} string stored in object metadata
     */
    byte[] decryptDataKey(String encryptedDek) throws Exception {
        var body = new JsonObject();
        body.addProperty("ciphertext", encryptedDek);

        String resp = post(addr + "/v1/transit/decrypt/" + keyName,
                body.toString());
        String b64 = JsonParser.parseString(resp)
                .getAsJsonObject()
                .getAsJsonObject("data")
                .get("plaintext").getAsString();

        return Base64.getDecoder().decode(b64);
    }

    private String post(String url, String body) throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .timeout(TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        var resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new RuntimeException(
                    "Vault POST " + url + " → HTTP " + resp.statusCode()
                    + ": " + resp.body());
        }
        return resp.body();
    }
}
