package com.crushed.core;

import burp.api.montoya.logging.Logging;
import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.Severity;
import com.crushed.model.Signal;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.Set;

/** Orchestrates: update EndpointRegistry, run every analyzer, correlate, prioritize, store findings. */
public final class AnalysisPipeline {

    private final EndpointRegistry registry;
    private final List<Analyzer> analyzers;
    private final Logging logging;
    private final ActivityLog activityLog;
    private final TriageStore triageStore;

    public AnalysisPipeline(EndpointRegistry registry, List<Analyzer> analyzers, Logging logging, ActivityLog activityLog) {
        this(registry, analyzers, logging, activityLog, new TriageStore());
    }

    public AnalysisPipeline(EndpointRegistry registry, List<Analyzer> analyzers, Logging logging,
                             ActivityLog activityLog, TriageStore triageStore) {
        this.registry = registry;
        this.analyzers = analyzers;
        this.logging = logging;
        this.activityLog = activityLog;
        this.triageStore = triageStore;
    }

    public void process(AnalysisContext context) {
        if (context == null) return;
        try {
            String pathTemplate = RequestFingerprint.normalizePathTemplate(context.path());
            registry.recordSighting(
                    context.host(),
                    context.method(),
                    pathTemplate,
                    context.historyId(),
                    Set.copyOf(context.requestParamNames()),
                    guessAuthScheme(context),
                    context.responseMimeType()
            );

            RequestFingerprint fingerprint = new RequestFingerprint(
                    context.host(), context.method(), pathTemplate,
                    Set.copyOf(context.requestParamNames()), guessAuthScheme(context),
                    context.responseMimeType(), context.responseMimeType(), context.responseStatusCode()
            );

            HostNotes hostNotes = registry.hostNotesFor(context.host());

            for (Analyzer analyzer : analyzers) {
                runAnalyzerSafely(analyzer, context, fingerprint, hostNotes);
            }
        } catch (Exception e) {
            reportError("AnalysisPipeline", context.historyId(), e);
        }
    }

    private void runAnalyzerSafely(Analyzer analyzer, AnalysisContext context, RequestFingerprint fingerprint, HostNotes hostNotes) {
        try {
            List<Signal> signals = analyzer.analyze(context, fingerprint);
            if (signals == null) return;
            for (Signal signal : signals) {
                Finding finding = toPotentialFinding(signal, context);
                hostNotes.addOrMergeFinding(finding);
            }
        } catch (Exception e) {
            reportError(analyzer.name(), context.historyId(), e);
        }
    }

    private Finding toPotentialFinding(Signal signal, AnalysisContext context) {
        String dedupeKey = signal.issueType() + "|" + signal.endpointKey() + "|" + signal.evidence().paramOrFieldName();
        Severity severity = SeverityMatrix.severityFor(signal.issueType());
        Finding finding = new Finding(
                dedupeKey,
                signal.issueType(),
                signal.endpointKey(),
                severity,
                signal.confidence(),
                com.crushed.model.Status.POTENTIAL,
                signal.issueType().defaultOwaspRef(),
                signal.rationale(),
                RemediationCatalog.forIssueType(signal.issueType()),
                List.of(signal.evidence())
        );
        var persistedState = triageStore.get(dedupeKey);
        if (persistedState != null) {
            finding.setTriageState(persistedState);
        }
        return finding;
    }

    private String guessAuthScheme(AnalysisContext context) {
        String auth = context.requestHeaders() == null ? null : context.requestHeaders().get("Authorization");
        if (auth != null) {
            if (auth.startsWith("Bearer")) return "bearer";
            if (auth.startsWith("Basic")) return "basic";
            return "other";
        }
        if (context.requestHeaders() != null && context.requestHeaders().containsKey("Cookie")) return "cookie";
        return null;
    }

    private void reportError(String module, int historyId, Exception e) {
        String message = "[" + module + "] Req #" + historyId + ": " + e;
        if (logging != null) {
            logging.logToError(message);
        }
        if (activityLog != null) {
            activityLog.error(module, historyId, message);
        }
    }
}
