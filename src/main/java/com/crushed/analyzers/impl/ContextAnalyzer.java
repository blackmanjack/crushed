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
import java.util.Set;

public final class ContextAnalyzer implements Analyzer {

    private static final Set<String> OPEN_REDIRECT_PARAMS = Set.of("backurl", "redirect", "returnurl", "next", "url", "dest");

    @Override
    public String name() {
        return "ContextAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        String path = context.path() == null ? "" : context.path();
        String host = context.host() == null ? "" : context.host();
        String responseBody = context.responseBody() == null ? "" : context.responseBody();

        // Firebase misconfiguration hints
        if (path.contains("/__/firebase/init.json")
                || host.contains("firebaseio.com")
                || host.contains("firestore.googleapis.com")
                || host.contains("firebasestorage")) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    "Firebase-related endpoint observed: " + path, null);
            signals.add(new Signal(IssueType.FIREBASE_MISCONFIGURATION, endpointKey, Confidence.TENTATIVE,
                    "Firebase project surface detected (init.json/Firestore/Storage host) — verify security rules " +
                            "aren't left at default allow-all.", evidence));
        }

        // XML/office upload surface (generalized XXE hint beyond xlsx). The upload endpoint's own
        // path rarely carries a file extension (e.g. /personal/CombineExcelUpload) — the evidence
        // is the multipart upload itself, or an XML/SOAP content-type on non-upload endpoints.
        String contentType = context.requestHeaders() == null ? "" : context.requestHeaders().getOrDefault("Content-Type", "");
        String requestBody = context.requestBody() == null ? "" : context.requestBody();
        boolean multipartWithOfficeFilename = contentType.contains("multipart/form-data") &&
                (requestBody.contains(".xlsx") || requestBody.contains(".docx") || requestBody.contains(".svg")
                        || requestBody.contains(".pptx") || path.toLowerCase().contains("upload"));
        boolean xmlUploadLike = multipartWithOfficeFilename || contentType.contains("xml") || contentType.contains("soap");
        if (xmlUploadLike) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                    "Content-Type suggests XML-based document processed server-side: " + contentType, "Content-Type");
            signals.add(new Signal(IssueType.XXE, endpointKey, Confidence.TENTATIVE,
                    "Endpoint appears to accept/process an XML-based document (xlsx/docx/svg/xml/soap are zip-of-xml " +
                            "or raw XML) — candidate for XXE if the parser resolves external entities.", evidence));
        }

        // Open redirect / DOM XSS chain param hint
        if (context.requestParamNames() != null) {
            for (String param : context.requestParamNames()) {
                if (OPEN_REDIRECT_PARAMS.contains(param.toLowerCase())) {
                    Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                            "redirect-like parameter: " + param, param);
                    signals.add(new Signal(IssueType.OPEN_REDIRECT, endpointKey, Confidence.TENTATIVE,
                            "Parameter '" + param + "' looks like a redirect target; check whether it's used unsafely " +
                                    "in location.assign/href (DOM XSS chain) or as a raw 3xx redirect.", evidence));
                }
            }
        }

        // AI session (Gemini-style) misconfiguration hint over WebSocket upgrade or token-mint response
        if (host.contains("generativelanguage.googleapis.com") || path.contains("BidiGenerateContent")) {
            boolean hasConstraints = responseBody.contains("live_connect_constraints") || responseBody.contains("bidi_generate_content_setup");
            if (!hasConstraints) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                        "token-mint response missing live_connect_constraints/bidi_generate_content_setup", null);
                signals.add(new Signal(IssueType.AI_SESSION_MISCONFIGURATION, endpointKey, Confidence.TENTATIVE,
                        "AI live-session token response has no visible server-side setup constraints — client may be " +
                                "able to override system prompt/tools (e.g. enable codeExecution).", evidence));
            }
        }

        return signals;
    }
}
