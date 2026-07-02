package com.crushed.oast;

import com.crushed.model.IssueType;

/** A probe that was sent embedding an OAST payload domain, awaiting a matching callback. */
public record PendingProbe(
        String correlationId,
        int historyId,
        String endpointKey,
        IssueType issueType,
        String technique
) {
}
