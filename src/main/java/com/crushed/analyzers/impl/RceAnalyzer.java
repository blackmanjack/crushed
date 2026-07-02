package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.Set;

public final class RceAnalyzer implements Analyzer {

    private static final Set<String> RCE_PARAM_HINTS = Set.of("cmd", "command", "exec", "convert", "export", "filename");

    @Override
    public String name() {
        return "RceAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.requestParamNames() == null) return List.of();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        for (String param : context.requestParamNames()) {
            if (RCE_PARAM_HINTS.contains(param.toLowerCase())) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                        "parameter name suggests command/file processing: " + param, param);
                return List.of(new Signal(IssueType.RCE, endpointKey, Confidence.TENTATIVE,
                        "Parameter '" + param + "' suggests server-side command execution or file conversion — " +
                                "candidate for command injection/RCE.",
                        evidence));
            }
        }
        return List.of();
    }
}
