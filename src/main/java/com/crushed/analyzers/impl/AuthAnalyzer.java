package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.EvidenceLocator;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Phase 2: passive IDOR/BOLA heuristic — sequential numeric ID in path/query touching user-owned data. */
public final class AuthAnalyzer implements Analyzer {

    private static final Pattern ID_IN_PATH = Pattern.compile("/(\\d{1,12})(?:/|$)");

    @Override
    public String name() {
        return "AuthAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.path() == null) return List.of();
        Matcher m = ID_IN_PATH.matcher(context.path());
        if (!m.find()) return List.of();
        if (context.responseStatusCode() < 200 || context.responseStatusCode() >= 300) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        Evidence evidence = EvidenceLocator.fromRequest(context.historyId(), context.requestRaw(), m.start(1), "path-id");

        return List.of(new Signal(
                IssueType.IDOR_BOLA,
                endpointKey,
                Confidence.TENTATIVE,
                "Numeric identifier '" + m.group(1) + "' in path is a candidate for IDOR/BOLA; " +
                        "server-side object-level authorization has not been verified passively.",
                evidence
        ));
    }
}
