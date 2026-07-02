package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;

import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * Builds a "send this payload as the whole request body" function from a stored original
 * request — used for XXE (DOCTYPE/entity payload replacing the XML/office body) and RCE
 * (command payload replacing a body field) where a single named parameter isn't the right
 * substitution unit. Gated by activeModeEnabled + ScopeGate, same as the other senders.
 */
public final class BodySubstitutingSender {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public BodySubstitutingSender(MontoyaApi api, ScopeGate scopeGate, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    public Function<String, ReplayResult> forBody(RequestStore.Stored original) {
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
                HttpRequest modified = baseRequest.withBody(payload);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result.response() == null) {
                    return ReplayResult.error("No response received.");
                }
                return ReplayResult.ok(result.response().statusCode(), result.response().bodyToString());
            } catch (Exception e) {
                activityLog.error("BodySubstitutingSender", 0, "Send failed: " + e);
                return ReplayResult.error(e.toString());
            }
        };
    }
}
