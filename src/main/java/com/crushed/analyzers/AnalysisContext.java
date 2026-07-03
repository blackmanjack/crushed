package com.crushed.analyzers;

import java.util.List;
import java.util.Map;

/**
 * Plain-data view of one HTTP request/response (or WS message) handed to every analyzer.
 * Decoupled from Montoya types so analyzers stay unit-testable without a live MontoyaApi.
 */
public record AnalysisContext(
        int historyId,
        String host,
        String method,
        String path,
        String requestRaw,
        String responseRaw,
        int responseStatusCode,
        Map<String, String> requestHeaders,
        Map<String, String> responseHeaders,
        List<String> requestParamNames,
        String requestBody,
        String responseBody,
        String responseMimeType,
        boolean isWebSocketFrame,
        int wsFrameIndex,
        boolean isHttps
) {
    public static AnalysisContext http(int historyId, String host, String method, String path,
                                        String requestRaw, String responseRaw, int status,
                                        Map<String, String> reqHeaders, Map<String, String> respHeaders,
                                        List<String> paramNames, String reqBody, String respBody,
                                        String responseMimeType, boolean isHttps) {
        return new AnalysisContext(historyId, host, method, path, requestRaw, responseRaw, status,
                reqHeaders, respHeaders, paramNames, reqBody, respBody, responseMimeType, false, -1, isHttps);
    }

    public static AnalysisContext wsFrame(int historyId, String host, int frameIndex, String frameText) {
        return new AnalysisContext(historyId, host, "WS", "", "", frameText, 0,
                Map.of(), Map.of(), List.of(), "", frameText, "text/plain", true, frameIndex, false);
    }
}
