package com.crushed.ai;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Minimal Anthropic Messages API client for the second-brain analysis feature.
 * Model is fixed to claude-opus-4-8 per the plan. Never called unless the AI toggle is on
 * and the user has supplied an API key; every input is pre-redacted by Redactor upstream.
 */
public final class ClaudeClient {

    private static final String MODEL = "claude-opus-4-8";
    private static final String ENDPOINT = "https://api.anthropic.com/v1/messages";
    private static final String ANTHROPIC_VERSION = "2023-06-01";

    private final String apiKey;
    private final HttpClient httpClient;
    private final Gson gson = new Gson();

    public ClaudeClient(String apiKey) {
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
    }

    /** Sends a single-turn text request and returns Claude's text response. Throws on failure. */
    public String complete(String userMessage, int maxTokens) throws Exception {
        JsonObject message = new JsonObject();
        message.addProperty("role", "user");
        message.addProperty("content", userMessage);
        JsonArray messages = new JsonArray();
        messages.add(message);

        JsonObject body = new JsonObject();
        body.addProperty("model", MODEL);
        body.addProperty("max_tokens", maxTokens);
        body.add("messages", messages);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(ENDPOINT))
                .header("Content-Type", "application/json")
                .header("x-api-key", apiKey)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
                .timeout(Duration.ofSeconds(60))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Claude API returned HTTP " + response.statusCode() + ": " + response.body());
        }

        JsonObject responseJson = gson.fromJson(response.body(), JsonObject.class);
        JsonArray content = responseJson.getAsJsonArray("content");
        StringBuilder text = new StringBuilder();
        for (var element : content) {
            JsonObject block = element.getAsJsonObject();
            if ("text".equals(block.get("type").getAsString())) {
                text.append(block.get("text").getAsString());
            }
        }
        return text.toString();
    }
}
