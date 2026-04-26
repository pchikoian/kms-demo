package com.demo.s3proxy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class VaultTransitClientTest {

    private HttpServer server;
    private VaultTransitClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private VaultTransitClient clientForServer() {
        int port = server.getAddress().getPort();
        return new VaultTransitClient("http://localhost:" + port, "test-token", "demo-kek");
    }

    // -------------------------------------------------------------------------
    // generateDataKey
    // -------------------------------------------------------------------------

    @Test
    void generateDataKey_parsesPlaintextAndCiphertext() throws Exception {
        byte[] rawDek = new byte[32];
        rawDek[0] = 0x42;
        String b64 = Base64.getEncoder().encodeToString(rawDek);

        stubPost("/v1/transit/datakey/plaintext/demo-kek", 200,
                "{\"data\":{\"plaintext\":\"" + b64 + "\",\"ciphertext\":\"vault:v1:abc123\"}}");

        VaultTransitClient.DataKey dk = clientForServer().generateDataKey();

        assertArrayEquals(rawDek, dk.plaintext());
        assertEquals("vault:v1:abc123", dk.ciphertext());
    }

    @Test
    void generateDataKey_sendsVaultToken() throws Exception {
        AtomicReference<String> capturedToken = new AtomicReference<>();
        byte[] rawDek = new byte[32];
        String b64 = Base64.getEncoder().encodeToString(rawDek);

        server.createContext("/v1/transit/datakey/plaintext/demo-kek", exchange -> {
            capturedToken.set(exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            respond(exchange, 200,
                    "{\"data\":{\"plaintext\":\"" + b64 + "\",\"ciphertext\":\"vault:v1:t\"}}");
        });
        server.start();

        clientForServer().generateDataKey();

        assertEquals("test-token", capturedToken.get());
    }

    @Test
    void generateDataKey_httpError_throwsRuntimeException() throws Exception {
        stubPost("/v1/transit/datakey/plaintext/demo-kek", 403,
                "{\"errors\":[\"permission denied\"]}");

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> clientForServer().generateDataKey());
        assertTrue(ex.getMessage().contains("403"));
    }

    // -------------------------------------------------------------------------
    // decryptDataKey
    // -------------------------------------------------------------------------

    @Test
    void decryptDataKey_returnsDecodedBytes() throws Exception {
        byte[] rawDek = new byte[32];
        rawDek[5] = 0x7F;
        String b64 = Base64.getEncoder().encodeToString(rawDek);
        AtomicReference<String> capturedBody = new AtomicReference<>();

        server.createContext("/v1/transit/decrypt/demo-kek", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes()));
            respond(exchange, 200, "{\"data\":{\"plaintext\":\"" + b64 + "\"}}");
        });
        server.start();

        byte[] result = clientForServer().decryptDataKey("vault:v1:xyz789");

        assertArrayEquals(rawDek, result);
        assertTrue(capturedBody.get().contains("vault:v1:xyz789"),
                "Request body must include the encrypted DEK ciphertext");
    }

    @Test
    void decryptDataKey_httpError_throwsRuntimeException() throws Exception {
        stubPost("/v1/transit/decrypt/demo-kek", 400,
                "{\"errors\":[\"invalid ciphertext\"]}");

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> clientForServer().decryptDataKey("vault:v1:bad"));
        assertTrue(ex.getMessage().contains("400"));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void stubPost(String path, int status, String body) throws Exception {
        server.createContext(path, exchange -> respond(exchange, status, body));
        server.start();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws java.io.IOException {
        exchange.getRequestBody().readAllBytes();   // drain request body
        byte[] bytes = body.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
