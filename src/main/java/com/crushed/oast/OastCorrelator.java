package com.crushed.oast;

import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.Severity;
import com.crushed.model.Status;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.crushed.core.SeverityMatrix.severityFor;

/**
 * Maps incoming OAST interactions back to the probe (Req #id, endpoint, issue type) that
 * planted the payload domain. A matching interaction is proof of an out-of-band vulnerability
 * (blind XXE/SSRF/SQLi/RCE) — this is what lets crushed confirm findings a purely in-band
 * scanner cannot.
 */
public final class OastCorrelator {

    private final Map<String, PendingProbe> pendingByCorrelationId = new ConcurrentHashMap<>();

    public void registerProbe(PendingProbe probe) {
        pendingByCorrelationId.put(probe.correlationId(), probe);
    }

    public List<Finding> correlate(List<Interaction> interactions) {
        List<Finding> findings = new ArrayList<>();
        for (Interaction interaction : interactions) {
            PendingProbe probe = pendingByCorrelationId.get(interaction.correlationId());
            if (probe == null) continue;

            Evidence evidence = Evidence.of(probe.historyId(), Evidence.Source.RESPONSE, 0,
                    "OAST callback: protocol=" + interaction.protocol() + " from=" + interaction.remoteAddress()
                            + " at=" + interaction.timestamp(), null);

            Finding finding = new Finding(
                    "OAST|" + probe.endpointKey() + "|" + probe.issueType(),
                    probe.issueType(),
                    probe.endpointKey(),
                    severityFor(probe.issueType()),
                    Confidence.CERTAIN,
                    Status.CONFIRMED,
                    probe.issueType().defaultOwaspRef(),
                    "Out-of-band interaction received on the payload domain planted via " + probe.technique()
                            + " — this proves server-side execution/resolution of attacker-controlled input, " +
                            "independent of any in-band response.",
                    com.crushed.core.RemediationCatalog.forIssueType(probe.issueType()),
                    List.of(evidence)
            );
            findings.add(finding);
        }
        return findings;
    }

    public int pendingCount() {
        return pendingByCorrelationId.size();
    }
}
