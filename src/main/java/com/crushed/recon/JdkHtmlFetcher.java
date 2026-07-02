package com.crushed.recon;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Function;

/** Real HTML fetcher for YandexDorker: queries yandex.com/search with a normal user-agent
 *  and a short delay between calls to stay a reasonable citizen. */
public final class JdkHtmlFetcher implements Function<String, String> {

    private static final String USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome Safari/537.36";
    private static final Duration DELAY_BETWEEN_REQUESTS = Duration.ofSeconds(5);

    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    @Override
    public String apply(String query) {
        try {
            String encoded = URLEncoder.encode(query, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://yandex.com/search/?text=" + encoded))
                    .header("User-Agent", USER_AGENT)
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Thread.sleep(DELAY_BETWEEN_REQUESTS.toMillis());
            return response.statusCode() == 200 ? response.body() : null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
