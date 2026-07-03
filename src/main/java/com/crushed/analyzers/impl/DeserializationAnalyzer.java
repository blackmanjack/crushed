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
 * Passive insecure-Java-deserialization heuristic: flags a request body/parameter carrying the
 * raw Java serialization magic bytes (0xACED0005) or its well-known base64-armored prefix
 * ("rO0AB"). Passive-only: actually exploiting deserialization needs gadget-chain payload
 * generation (ysoserial-style), a different, much larger tool category, explicitly out of scope
 * here (same boundary already documented for OAuthAnalyzer).
 */
public final class DeserializationAnalyzer implements Analyzer {

    // Built from char codes rather than a string literal, to avoid embedding raw control bytes
    // (0x00, 0x05) in the source file.
    private static final String RAW_MAGIC_BYTES = new String(new char[] {0x00AC, 0x00ED, 0x0000, 0x0005});
    private static final String BASE64_PREFIX = "rO0AB";

    @Override
    public String name() {
        return "DeserializationAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String requestBody = context.requestBody();
        if (requestBody == null || requestBody.isEmpty()) return List.of();

        int idx = requestBody.indexOf(RAW_MAGIC_BYTES);
        String matched = null;
        if (idx >= 0) {
            matched = "raw Java serialization magic bytes (0xACED0005)";
        } else {
            idx = requestBody.indexOf(BASE64_PREFIX);
            if (idx >= 0) {
                matched = "base64-armored Java serialized object prefix ('" + BASE64_PREFIX + "')";
            }
        }
        if (matched == null) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, idx,
                requestBody.substring(idx, Math.min(requestBody.length(), idx + 40)), null);

        return List.of(new Signal(IssueType.INSECURE_DESERIALIZATION, endpointKey, Confidence.TENTATIVE,
                "Request body contains " + matched + " — candidate for insecure Java deserialization if the " +
                        "server deserializes this value without validation.", evidence));
    }
}
