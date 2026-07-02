package com.crushed.detectors;

import com.crushed.model.Endpoint;
import com.crushed.model.Finding;

import java.util.List;

/**
 * Iterasi-2 contract: active detectors probe a live endpoint and return Findings with
 * Status=CONFIRMED on success. Not wired into the MVP pipeline; Active mode is disabled by
 * default and no implementation currently sends traffic.
 */
public interface ActiveDetector {

    String name();

    boolean applicable(Endpoint endpoint);

    List<Finding> probe(Endpoint endpoint);
}
