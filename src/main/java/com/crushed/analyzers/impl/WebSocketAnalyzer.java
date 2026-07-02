package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.List;

/** Analyzes WebSocket frames (via AnalysisContext.wsFrame) for AI-session-style setup abuse and sensitive data. */
public final class WebSocketAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "WebSocketAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (!context.isWebSocketFrame()) return List.of();
        String frame = context.responseBody() == null ? "" : context.responseBody();
        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " WS " + context.wsFrameIndex();

        boolean setupOverride = frame.contains("\"tools\"") && frame.contains("codeExecution");
        if (setupOverride) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.WS_FRAME, context.wsFrameIndex(),
                    "frame declares tools:[codeExecution]", null);
            signals.add(new Signal(IssueType.AI_SESSION_MISCONFIGURATION, endpointKey, Confidence.FIRM,
                    "WebSocket setup frame requests codeExecution tool — verify server enforces locked session constraints.",
                    evidence));
        }
        return signals;
    }
}
