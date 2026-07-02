package com.crushed.model;

import java.util.List;

/** A vulnerability hypothesis (or confirmed vuln) surfaced to the user. */
public final class Finding {

    private final String dedupeKey;
    private final IssueType issueType;
    private final String endpointKey;
    private final Severity severity;
    private final Confidence confidence;
    private final OwaspRef owaspRef;
    private final String rationale;
    private final String remediation;
    private final List<Evidence> evidence;

    private volatile Status status;
    private volatile TriageState triageState = TriageState.NEW;

    public Finding(String dedupeKey, IssueType issueType, String endpointKey, Severity severity,
                   Confidence confidence, Status status, OwaspRef owaspRef, String rationale,
                   String remediation, List<Evidence> evidence) {
        this.dedupeKey = dedupeKey;
        this.issueType = issueType;
        this.endpointKey = endpointKey;
        this.severity = severity;
        this.confidence = confidence;
        this.status = status;
        this.owaspRef = owaspRef;
        this.rationale = rationale;
        this.remediation = remediation;
        this.evidence = List.copyOf(evidence);
    }

    public void promoteToConfirmed() {
        this.status = Status.CONFIRMED;
    }

    public void setTriageState(TriageState state) {
        this.triageState = state;
    }

    public String dedupeKey() { return dedupeKey; }
    public IssueType issueType() { return issueType; }
    public String endpointKey() { return endpointKey; }
    public Severity severity() { return severity; }
    public Confidence confidence() { return confidence; }
    public Status status() { return status; }
    public TriageState triageState() { return triageState; }
    public OwaspRef owaspRef() { return owaspRef; }
    public String rationale() { return rationale; }
    public String remediation() { return remediation; }
    public List<Evidence> evidence() { return evidence; }
}
