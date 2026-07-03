package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;

/**
 * Passive server-side prototype-pollution candidate heuristic: flags a JSON request body
 * containing a "__proto__", "constructor.prototype", or "constructor[" key, mirroring
 * server-side-prototype-pollution's detection approach.
 */
public final class PrototypePollutionAnalyzer implements Analyzer {

    private static final String[] MARKERS = {"\"__proto__\"", "constructor.prototype", "constructor["};

    @Override
    public String name() {
        return "PrototypePollutionAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String mime = context.requestHeaders() == null ? "" : context.requestHeaders().getOrDefault("Content-Type", "");
        String requestBody = context.requestBody();
        if (requestBody == null || requestBody.isEmpty()) return List.of();
        if (!mime.toLowerCase().contains("json") && !requestBody.trim().startsWith("{")) return List.of();

        for (String marker : MARKERS) {
            int idx = requestBody.indexOf(marker);
            if (idx < 0) continue;

            String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, idx,
                    requestBody.substring(Math.max(0, idx - 20), Math.min(requestBody.length(), idx + 40)), null);
            return List.of(new Signal(IssueType.PROTOTYPE_POLLUTION, endpointKey, Confidence.TENTATIVE,
                    "JSON request body contains a '" + marker + "' key — candidate server-side prototype " +
                            "pollution if this object is merged into an application object without sanitization.",
                    evidence));
        }
        return List.of();
    }
}
