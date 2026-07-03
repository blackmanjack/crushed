package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import com.crushed.analyzers.AnalysisContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * Reads existing Proxy history on load, then hooks new traffic. Filters everything through
 * ScopeGate before it reaches the AnalysisPipeline. HTTP only in this pass; WebSocket hook
 * is wired the same way via registerWebSocketCreationHandler in CrushedExtension.
 */
public final class HistoryIngestor implements ProxyResponseHandler {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final AnalysisPipeline pipeline;
    private final RequestStore requestStore;
    private final SessionColorAssigner colorAssigner;
    private final BooleanSupplier colorCodingEnabled;

    public HistoryIngestor(MontoyaApi api, ScopeGate scopeGate, AnalysisPipeline pipeline, RequestStore requestStore,
                            SessionColorAssigner colorAssigner, BooleanSupplier colorCodingEnabled) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.pipeline = pipeline;
        this.requestStore = requestStore;
        this.colorAssigner = colorAssigner;
        this.colorCodingEnabled = colorCodingEnabled;
    }

    public void ingestExistingHistory() {
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            for (ProxyHttpRequestResponse item : history) {
                ingest(item.request(), item.response(), item.annotations());
            }
        } catch (Exception e) {
            api.logging().logToError("HistoryIngestor.ingestExistingHistory failed: " + e);
        }
    }

    /** Public entry point for traffic fetched outside the Proxy (crawl / site-map backfill), so it
     * runs through the exact same analyzer pipeline as regular Proxy traffic. */
    public void ingestFetched(HttpRequest request, HttpResponse response, Annotations annotations) {
        ingest(request, response, annotations);
    }

    private void ingest(HttpRequest request, HttpResponse response, Annotations annotations) {
        if (request == null) return;
        String url = request.url();
        if (!scopeGate.isInScope(url)) return;

        try {
            int historyId = requestStore.record(request, response);

            Map<String, String> reqHeaders = new HashMap<>();
            request.headers().forEach(h -> reqHeaders.put(h.name(), h.value()));

            Map<String, String> respHeaders = new HashMap<>();
            String responseMime = "";
            String responseBody = "";
            int status = 0;
            if (response != null) {
                response.headers().forEach(h -> respHeaders.put(h.name(), h.value()));
                responseMime = response.statedMimeType() != null ? response.statedMimeType().toString() : "";
                responseBody = response.bodyToString();
                status = response.statusCode();
            }

            List<String> paramNames = request.parameters().stream()
                    .map(ParsedHttpParameter::name)
                    .toList();

            applySessionHighlight(reqHeaders, annotations, historyId);

            AnalysisContext context = AnalysisContext.http(
                    historyId,
                    request.httpService() != null ? request.httpService().host() : "",
                    request.method(),
                    request.path(),
                    request.toString(),
                    response != null ? response.toString() : "",
                    status,
                    reqHeaders,
                    respHeaders,
                    paramNames,
                    request.bodyToString(),
                    responseBody,
                    responseMime,
                    request.httpService() != null && request.httpService().secure()
            );

            pipeline.process(context);
        } catch (Exception e) {
            api.logging().logToError("HistoryIngestor.ingest failed: " + e);
        }
    }

    /**
     * Colors this row in Burp's HTTP history by which session/account it belongs to (same
     * fingerprint used by SessionDiffAnalyzer), so the user can visually tell Account A traffic
     * from Account B traffic. Overwrites any highlight color already set on the row. Opt-out via
     * the Settings toggle; skipped entirely for requests with no Cookie/Authorization header.
     */
    private void applySessionHighlight(Map<String, String> reqHeaders, Annotations annotations, int historyId) {
        if (annotations == null || !colorCodingEnabled.getAsBoolean()) return;
        try {
            String fingerprint = SessionFingerprint.extract(reqHeaders);
            if (fingerprint == null) return;
            HighlightColor color = colorAssigner.colorFor(fingerprint);
            annotations.setHighlightColor(color);
        } catch (Exception e) {
            api.logging().logToError("HistoryIngestor.applySessionHighlight failed for Req #" + historyId + ": " + e);
        }
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            String url = interceptedResponse.initiatingRequest().url();
            if (scopeGate.isInScope(url)) {
                ingest(interceptedResponse.initiatingRequest(), interceptedResponse, interceptedResponse.annotations());
            }
        } catch (Exception e) {
            api.logging().logToError("HistoryIngestor.handleResponseReceived failed: " + e);
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
