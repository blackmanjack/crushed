package com.crushed.ai;

import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.ui.ActivityLog;

import java.util.List;

/**
 * Optional AI analysis layer: builds a redacted summary of a host's findings (never raw
 * traffic), sends it to Claude for correlation/tracing across Req #ids, and returns the
 * analysis tagged [AI] so it's clearly distinguished from the deterministic rule-engine output.
 * Only invoked when the user has enabled the AI toggle and supplied an API key; the core engine
 * functions identically whether or not this class is ever called.
 */
public final class AiAnalyst {

    private final ClaudeClient claudeClient;
    private final Redactor redactor;
    private final ActivityLog activityLog;

    public AiAnalyst(ClaudeClient claudeClient, Redactor redactor, ActivityLog activityLog) {
        this.claudeClient = claudeClient;
        this.redactor = redactor;
        this.activityLog = activityLog;
    }

    public String buildRedactedSummary(HostNotes hostNotes) {
        StringBuilder sb = new StringBuilder();
        sb.append("Host: ").append(hostNotes.host()).append("\n\n");
        appendFindings(sb, "CONFIRMED", hostNotes.confirmedFindings());
        appendFindings(sb, "POTENTIAL", hostNotes.potentialFindings());
        return sb.toString();
    }

    private void appendFindings(StringBuilder sb, String label, List<Finding> findings) {
        for (Finding finding : findings) {
            sb.append("[").append(label).append("] ").append(finding.issueType().displayName())
                    .append(" (").append(finding.severity()).append("/").append(finding.confidence()).append(")")
                    .append(" endpoint=").append(finding.endpointKey()).append("\n");
            sb.append("  rationale: ").append(redactor.redact(finding.rationale())).append("\n");
            for (Evidence e : finding.evidence()) {
                sb.append("  Req #").append(e.historyId()).append(" @ ").append(e.source())
                        .append(":").append(e.lineOrOffset())
                        .append(" -> ").append(redactor.redact(e.snippet())).append("\n");
            }
        }
    }

    /** Runs the analysis; returns null (and logs) on any failure rather than throwing. */
    public String analyze(HostNotes hostNotes) {
        String summary = buildRedactedSummary(hostNotes);
        String prompt = "You are assisting a penetration tester reviewing findings from an automated " +
                "Burp Suite extension called crushed. Below is a REDACTED summary of findings for one host " +
                "(secrets/tokens already masked). Correlate related findings across Req #ids, point out any " +
                "chain of vulnerabilities, and suggest concrete next steps. Reference Req #ids in your answer.\n\n" +
                summary;
        try {
            String result = claudeClient.complete(prompt, 2000);
            return "[AI]\n" + result;
        } catch (Exception e) {
            activityLog.error("AiAnalyst", -1, "Claude analysis failed: " + e);
            return null;
        }
    }
}
