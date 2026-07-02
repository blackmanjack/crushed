package com.crushed.oast;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Minimal Interactsh (ProjectDiscovery) client: generates a keypair, registers with the OAST
 * server, and polls for interactions. Default public instance is oast.pro; self-hosted/oast.live
 * are configurable via the constructor. Network calls are guarded — any failure is surfaced by
 * the caller's ActivityLog, never thrown past this boundary in poll().
 */
public final class InteractshClient {

    private final String serverHost;
    private final HttpClient httpClient;
    private final Gson gson = new Gson();
    private final KeyPair keyPair;
    private final String correlationId;
    private final String secretKey;

    public InteractshClient(String serverHost) {
        this.serverHost = serverHost;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.keyPair = generateKeyPair();
        this.correlationId = randomLowerAlphaNum(20);
        this.secretKey = UUID.randomUUID().toString();
    }

    /** The payload domain to embed in probes, e.g. "<correlationId>.oast.pro". */
    public String payloadDomain() {
        return correlationId + "." + serverHost;
    }

    public String correlationId() {
        return correlationId;
    }

    public void register() throws Exception {
        String publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        JsonObject body = new JsonObject();
        body.addProperty("public-key", publicKeyB64);
        body.addProperty("secret-key", secretKey);
        body.addProperty("correlation-id", correlationId);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + serverHost + "/register"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
                .timeout(Duration.ofSeconds(15))
                .build();

        httpClient.send(request, HttpResponse.BodyHandlers.discarding());
    }

    /** Polls once; returns decrypted interactions. Never throws — errors come back as an empty list. */
    public List<Interaction> poll() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + serverHost + "/poll?id=" + correlationId + "&secret=" + secretKey))
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) return List.of();

            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json == null || !json.has("data") || json.get("data").isJsonNull()) return List.of();

            String aesKeyB64 = json.has("aes_key") ? json.get("aes_key").getAsString() : null;
            List<Interaction> interactions = new ArrayList<>();
            for (var element : json.getAsJsonArray("data")) {
                String encrypted = element.getAsString();
                String decrypted = decrypt(encrypted, aesKeyB64);
                if (decrypted == null) continue;
                JsonObject entry = gson.fromJson(decrypted, JsonObject.class);
                interactions.add(new Interaction(
                        correlationId,
                        entry.has("protocol") ? entry.get("protocol").getAsString() : "unknown",
                        entry.has("remote-address") ? entry.get("remote-address").getAsString() : "",
                        Instant.now(),
                        decrypted
                ));
            }
            return interactions;
        } catch (Exception e) {
            return List.of();
        }
    }

    private String decrypt(String encryptedBase64, String aesKeyB64) {
        try {
            if (aesKeyB64 == null) return null;
            byte[] encryptedAesKey = Base64.getDecoder().decode(aesKeyB64);
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] aesKey = rsaCipher.doFinal(encryptedAesKey);

            byte[] data = Base64.getDecoder().decode(encryptedBase64);
            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, 16);
            byte[] cipherText = new byte[data.length - 16];
            System.arraycopy(data, 16, cipherText, 0, cipherText.length);

            Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
            byte[] plain = aesCipher.doFinal(cipherText);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA keypair for Interactsh client", e);
        }
    }

    private String randomLowerAlphaNum(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(ThreadLocalRandom.current().nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
