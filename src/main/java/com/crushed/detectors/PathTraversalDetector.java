package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Active path-traversal confirmation: send a traversal payload targeting a known-readable OS
 * file (via WafBypassEngine's auto-bypass retry) and check the response for a recognizable file
 * content/error signature that proves the payload reached the filesystem.
 */
public final class PathTraversalDetector {

    private static final String PAYLOAD = "../../../../../../etc/passwd";

    private static final Pattern FILE_LEAK_SIGNATURE = Pattern.compile(
            "root:.*:0:0:|\\[boot loader\\]|\\[extensions\\]", Pattern.CASE_INSENSITIVE);

    private final WafBypassEngine bypassEngine;
    private final ActivityLog activityLog;

    public PathTraversalDetector(WafBypassEngine bypassEngine, ActivityLog activityLog) {
        this.bypassEngine = bypassEngine;
        this.activityLog = activityLog;
    }

    public List<Finding> probe(int historyId, String endpointKey, String paramName, Function<String, ReplayResult> sender) {
        WafBypassEngine.Outcome outcome = bypassEngine.sendWithAutoBypass(
                historyId, "PathTraversalDetector", PAYLOAD, sender,
                r -> !r.networkError() && FILE_LEAK_SIGNATURE.matcher(r.body()).find());

        if (!outcome.confirmed()) {
            return List.of();
        }

        var matcher = FILE_LEAK_SIGNATURE.matcher(outcome.finalResult().body());
        String snippet = matcher.find()
                ? outcome.finalResult().body().substring(Math.max(0, matcher.start() - 20), Math.min(outcome.finalResult().body().length(), matcher.end() + 40))
                : "";

        Evidence evidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "technique=" + outcome.techniqueUsed() + " leaked: " + snippet, paramName);

        Finding finding = new Finding(
                "PATH_TRAVERSAL|" + endpointKey + "|" + paramName,
                IssueType.PATH_TRAVERSAL,
                endpointKey,
                Severity.HIGH,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.PATH_TRAVERSAL,
                "Path traversal confirmed: parameter '" + paramName + "' resolves to a filesystem path outside " +
                        "the intended directory, leaking file content.",
                com.crushed.core.RemediationCatalog.forIssueType(IssueType.PATH_TRAVERSAL),
                List.of(evidence)
        );
        activityLog.bypassed("PathTraversalDetector", historyId, "Confirmed path traversal on " + endpointKey);
        return List.of(finding);
    }
}
