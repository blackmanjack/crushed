package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * Builds a "send this payload as parameter X" function from a stored original request, for use
 * with WafBypassEngine/SqliDetector/XssDetector. Gated by activeModeEnabled + ScopeGate, same as
 * MontoyaRequestSender — this is the second (and only other) place that sends live traffic.
 */
public final class ParameterSubstitutingSender {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public ParameterSubstitutingSender(MontoyaApi api, ScopeGate scopeGate, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    public Function<String, ReplayResult> forParameter(RequestStore.Stored original, String paramName) {
        return payload -> {
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
                ParsedHttpParameter existing = baseRequest.parameters().stream()
                        .filter(p -> p.name().equals(paramName))
                        .findFirst()
                        .orElse(null);
                if (existing == null) {
                    return ReplayResult.error("Parameter '" + paramName + "' not found on original request.");
                }

                HttpParameter updated = HttpParameter.parameter(paramName, payload, existing.type());
                HttpRequest modified = baseRequest.withUpdatedParameters(updated);

                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result.response() == null) {
                    return ReplayResult.error("No response received.");
                }
                Map<String, String> headers = new HashMap<>();
                result.response().headers().forEach(h -> headers.put(h.name(), h.value()));
                return ReplayResult.ok(result.response().statusCode(), result.response().bodyToString(), headers);
            } catch (Exception e) {
                activityLog.error("ParameterSubstitutingSender", 0, "Send failed for param=" + paramName + ": " + e);
                return ReplayResult.error(e.toString());
            }
        };
    }
}
