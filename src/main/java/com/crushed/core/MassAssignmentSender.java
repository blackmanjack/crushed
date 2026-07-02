package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;

import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Injects an extra field into a stored PUT/PATCH request's JSON body, sends it, then sends a
 * follow-up GET to the same URL (same auth) to check whether the injected value persisted. Both
 * results are handed to MassAssignmentDetector for the confirm/no-confirm decision. Gated by
 * activeModeEnabled + ScopeGate, same as every other active sender in this extension.
 */
public final class MassAssignmentSender {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final BooleanSupplier activeModeEnabled;

    public record ProbeResult(ReplayResult writeResponse, ReplayResult readResponse) {
    }

    public MassAssignmentSender(MontoyaApi api, ScopeGate scopeGate, BooleanSupplier activeModeEnabled) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.activeModeEnabled = activeModeEnabled;
    }

    public ProbeResult probe(RequestStore.Stored original, String fieldName, String markerValue) {
        if (!activeModeEnabled.getAsBoolean()) {
            return new ProbeResult(ReplayResult.error("Active mode is disabled; refusing to send."), null);
        }
        if (original == null || original.request() == null) {
            return new ProbeResult(ReplayResult.error("No stored original request for this finding."), null);
        }

        HttpRequest baseRequest = original.request();
        if (!scopeGate.isInScope(baseRequest.url())) {
            return new ProbeResult(ReplayResult.error("Host is out of scope; refusing to send."), null);
        }

        ReplayResult writeResult;
        try {
            String injectedBody = injectField(baseRequest.bodyToString(), fieldName, markerValue);
            HttpRequest modified = baseRequest.withBody(injectedBody);
            HttpRequestResponse result = api.http().sendRequest(modified);
            writeResult = result.response() == null
                    ? ReplayResult.error("No response received for write.")
                    : ReplayResult.ok(result.response().statusCode(), result.response().bodyToString());
        } catch (Exception e) {
            return new ProbeResult(ReplayResult.error(e.toString()), null);
        }

        ReplayResult readResult;
        try {
            HttpRequest getRequest = baseRequest.withMethod("GET").withBody("");
            HttpRequestResponse result = api.http().sendRequest(getRequest);
            readResult = result.response() == null
                    ? null
                    : ReplayResult.ok(result.response().statusCode(), result.response().bodyToString());
        } catch (Exception e) {
            readResult = null;
        }

        return new ProbeResult(writeResult, readResult);
    }

    /** Regex-based injection: overwrite the field if present, else insert it after the opening brace. */
    private String injectField(String body, String fieldName, String markerValue) {
        if (body == null || body.isBlank()) {
            return "{\"" + fieldName + "\":\"" + markerValue + "\"}";
        }
        Pattern existing = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*(\"[^\"]*\"|[^,}]+)");
        Matcher matcher = existing.matcher(body);
        if (matcher.find()) {
            return matcher.replaceFirst(Matcher.quoteReplacement("\"" + fieldName + "\":\"" + markerValue + "\""));
        }
        int braceIndex = body.indexOf('{');
        if (braceIndex < 0) {
            return body;
        }
        return body.substring(0, braceIndex + 1) + "\"" + fieldName + "\":\"" + markerValue + "\","
                + body.substring(braceIndex + 1);
    }
}
