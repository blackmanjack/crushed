package com.crushed.analyzers;

import java.util.List;
import java.util.Map;

final class TestFixtures {

    private TestFixtures() {
    }

    static AnalysisContext http(String host, String method, String path, int status,
                                Map<String, String> reqHeaders, Map<String, String> respHeaders,
                                List<String> params, String reqBody, String respBody, String mime) {
        return http(host, method, path, status, reqHeaders, respHeaders, params, reqBody, respBody, mime, false);
    }

    static AnalysisContext http(String host, String method, String path, int status,
                                Map<String, String> reqHeaders, Map<String, String> respHeaders,
                                List<String> params, String reqBody, String respBody, String mime, boolean isHttps) {
        return AnalysisContext.http(1, host, method, path, reqBody, respBody,
                status, reqHeaders, respHeaders, params, reqBody, respBody, mime, isHttps);
    }
}
