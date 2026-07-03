package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * Builds a "send this 403/401-bypass variant" function from a stored original request, for use
 * with ForbiddenBypassDetector. Gated by activeModeEnabled + ScopeGate, same pattern as
 * ParameterSubstitutingSender. The variant key selects a path-manipulation or header-spoofing
 * trick; unknown keys are treated as a no-op (send the request unmodified).
 */
public final class ForbiddenBypassSender {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public ForbiddenBypassSender(MontoyaApi api, ScopeGate scopeGate, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    public Function<String, ReplayResult> forRequest(RequestStore.Stored original) {
        return variant -> {
            if (!activeModeEnabled.getAsBoolean()) {
                return ReplayResult.error("Active mode is disabled; refusing to send.");
            }
            if (original == null || original.request() == null) {
                return ReplayResult.error("No stored original request for this finding.");
            }
            HttpRequest baseRequest = original.request();
            if (!scopeGate.isInScope(baseRequest.url())) {
                return ReplayResult.error("Host is out of scope; refusing to send: " + baseRequest.httpService().host());
            }

            try {
                HttpRequest modified = applyVariant(baseRequest, variant);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result.response() == null) {
                    return ReplayResult.error("No response received.");
                }
                Map<String, String> headers = new HashMap<>();
                result.response().headers().forEach(h -> headers.put(h.name(), h.value()));
                return ReplayResult.ok(result.response().statusCode(), result.response().bodyToString(), headers);
            } catch (Exception e) {
                activityLog.error("ForbiddenBypassSender", 0, "Send failed for variant=" + variant + ": " + e);
                return ReplayResult.error(e.toString());
            }
        };
    }

    private HttpRequest applyVariant(HttpRequest baseRequest, String variant) {
        String path = baseRequest.path();
        return switch (variant) {
            case "trailing-dot" -> baseRequest.withPath(stripQuery(path) + "/." + query(path));
            case "double-slash" -> baseRequest.withPath("/" + stripQuery(path).replaceFirst("^/", "") + "/" + query(path));
            case "dot-segment" -> baseRequest.withPath(insertBeforeLastSegment(stripQuery(path), "%2e/") + query(path));
            case "x-original-url" -> baseRequest.withAddedHeader("X-Original-URL", path);
            case "x-rewrite-url" -> baseRequest.withAddedHeader("X-Rewrite-URL", path);
            case "x-forwarded-for" -> baseRequest.withAddedHeader("X-Forwarded-For", "127.0.0.1");
            default -> baseRequest;
        };
    }

    private String stripQuery(String path) {
        int q = path.indexOf('?');
        return q < 0 ? path : path.substring(0, q);
    }

    private String query(String path) {
        int q = path.indexOf('?');
        return q < 0 ? "" : path.substring(q);
    }

    private String insertBeforeLastSegment(String path, String insertion) {
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0) return insertion + path;
        return path.substring(0, lastSlash + 1) + insertion + path.substring(lastSlash + 1);
    }
}
