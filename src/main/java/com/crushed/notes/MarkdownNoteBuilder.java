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
            sb.append("### ").append(finding.issueType().displayName())
                    .append(" [").append(finding.severity()).append('/').append(finding.confidence()).append("]\n");
            sb.append("- Endpoint: `").append(finding.endpointKey()).append("`\n");
            sb.append("- OWASP: ").append(finding.owaspRef().owaspTop10());
            if (finding.owaspRef().owaspApiTop10() != null) sb.append(" / ").append(finding.owaspRef().owaspApiTop10());
            sb.append(" | WSTG: ").append(finding.owaspRef().wstgId());
            sb.append(" | CWE: ").append(finding.owaspRef().cwe()).append('\n');
            sb.append("- Rationale: ").append(finding.rationale()).append('\n');
            sb.append("- Remediation: ").append(finding.remediation()).append('\n');
            for (Evidence e : finding.evidence()) {
                sb.append("  - Req #").append(e.historyId()).append(" @ ").append(e.source())
                        .append(":").append(e.lineOrOffset());
                if (e.paramOrFieldName() != null) sb.append(" (param=").append(e.paramOrFieldName()).append(')');
                sb.append(" — `").append(e.snippet()).append("`\n");
            }
            sb.append('\n');
        }
    }
}
