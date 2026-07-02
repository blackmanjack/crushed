package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Signal;

import java.util.List;

/** Phase 1: classification only. Does not itself emit vuln signals; other analyzers rely on the fingerprint. */
public final class FingerprintAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "FingerprintAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        return List.of();
    }
}
