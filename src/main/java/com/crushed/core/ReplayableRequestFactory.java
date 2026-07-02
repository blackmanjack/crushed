package com.crushed.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.identitydiff.ReplayableRequest;

import java.util.HashMap;
import java.util.Map;

/** Converts stored Montoya request/response objects into the Montoya-independent
 *  identitydiff types, so IdentityReplayEngine stays testable without a live MontoyaApi. */
public final class ReplayableRequestFactory {

    private ReplayableRequestFactory() {
    }

    public static ReplayableRequest from(int historyId, HttpRequest request) {
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(h -> headers.put(h.name(), h.value()));
        String host = request.httpService() != null ? request.httpService().host() : "";
        return new ReplayableRequest(historyId, host, request.method(), request.path(), headers, request.bodyToString());
    }

    public static ReplayResult originalResultFrom(HttpResponse response) {
        if (response == null) {
            return ReplayResult.error("No original response stored for this request.");
        }
        return ReplayResult.ok(response.statusCode(), response.bodyToString());
    }
}
