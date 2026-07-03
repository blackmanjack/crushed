package com.crushed.notes;

import com.crushed.model.Endpoint;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;

import java.util.List;

/** Renders a HostNotes into the second-brain Markdown format, split Confirmed vs Potential. */
public final class MarkdownNoteBuilder {

    public String render(HostNotes hostNotes) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(hostNotes.host()).append("\n\n");

        sb.append("## Endpoint Registry (").append(hostNotes.endpoints().size()).append(")\n\n");
        for (Endpoint endpoint : hostNotes.endpoints()) {
            sb.append("- `").append(endpoint.method()).append(' ').append(endpoint.pathTemplate()).append("` ")
                    .append("params=").append(endpoint.paramNames()).append(' ')
                    .append("auth=").append(endpoint.authSchemesSeen()).append(' ')
                    .append("reqs=").append(endpoint.historyIds()).append('\n');
        }

        sb.append("\n## ✅ Confirmed Vulnerabilities\n\n");
        appendFindings(sb, hostNotes.confirmedFindings());

        sb.append("\n## ❓ Potential / Needs Validation\n\n");
        appendFindings(sb, hostNotes.potentialFindings());

        return sb.toString();
    }

    private void appendFindings(StringBuilder sb, List<Finding> findings) {
        if (findings.isEmpty()) {
            sb.append("_(none)_\n\n");
            return;
        }
        for (Finding finding : findings) {
            sb.append(renderFinding(finding)).append('\n');
        }
    }

    /** Renders a single Finding as a Burp-Pro-style Advisory block: title/severity, Background
     * (rationale), Remediation, References, and evidence. Shared by the whole-host dump above and
     * the single-finding Advisory detail panel in CrushedTab. */
    public String renderFinding(Finding finding) {
        StringBuilder sb = new StringBuilder();
        sb.append("### ").append(finding.issueType().displayName())
                .append(" [").append(finding.severity()).append('/').append(finding.confidence()).append("]\n");
        sb.append("- Endpoint: `").append(finding.endpointKey()).append("`\n");
        sb.append("- Status: ").append(finding.status()).append(" | Triage: ").append(finding.triageState()).append('\n');
        sb.append("- Background: ").append(finding.rationale()).append('\n');
        sb.append("- Remediation: ").append(finding.remediation()).append('\n');
        sb.append("- References:\n");
        String owaspUrl = ReferenceLinks.owaspTop10Url(finding.owaspRef().owaspTop10());
        sb.append("  - OWASP Top 10: ").append(finding.owaspRef().owaspTop10());
        if (owaspUrl != null) sb.append(" — ").append(owaspUrl);
        sb.append('\n');
        if (finding.owaspRef().owaspApiTop10() != null) {
            sb.append("  - OWASP API Top 10: ").append(finding.owaspRef().owaspApiTop10()).append('\n');
        }
        sb.append("  - WSTG: ").append(ReferenceLinks.wstgReferenceText(finding.owaspRef().wstgId(), null)).append('\n');
        String cweUrl = ReferenceLinks.cweUrl(finding.owaspRef().cwe());
        sb.append("  - CWE: ").append(finding.owaspRef().cwe());
        if (cweUrl != null) sb.append(" — ").append(cweUrl);
        sb.append('\n');
        sb.append("- Evidence:\n");
        for (Evidence e : finding.evidence()) {
            sb.append("  - Req #").append(e.historyId()).append(" @ ").append(e.source())
                    .append(":").append(e.lineOrOffset());
            if (e.paramOrFieldName() != null) sb.append(" (param=").append(e.paramOrFieldName()).append(')');
            sb.append(" — `").append(e.snippet()).append("`\n");
        }
        return sb.toString();
    }
}
