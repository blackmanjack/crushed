package com.crushed.model;

/** A raw observation emitted by one analyzer, before prioritization/chaining. */
public record Signal(
        IssueType issueType,
        String endpointKey,
        Confidence confidence,
        String rationale,
        Evidence evidence
) {
}
