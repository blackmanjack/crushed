package com.crushed.analyzers;

import com.crushed.core.RequestFingerprint;
import com.crushed.model.Signal;

import java.util.List;

/** Pure, stateless passive analyzer. Implementations must never throw past this boundary. */
public interface Analyzer {

    String name();

    List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint);
}
