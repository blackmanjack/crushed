package com.crushed.core;

import com.crushed.detectors.BlockDetector;
import com.crushed.detectors.FirebaseDetector;
import com.crushed.detectors.MassAssignmentDetector;
import com.crushed.detectors.OastConfirmedDetector;
import com.crushed.detectors.PayloadVariantGenerator;
import com.crushed.detectors.SqliDetector;
import com.crushed.detectors.WafBypassEngine;
import com.crushed.detectors.XssDetector;
import com.crushed.model.*;
import com.crushed.oast.OastCorrelator;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ActiveConfirmationServiceFirebaseTest {

    @Test
    void reportsInfoWhenNoProjectIdCanBeExtracted() {
        RequestStore requestStore = new RequestStore();
        int id = requestStore.record(null, null);
        ActivityLog activityLog = new ActivityLog();
        ActiveConfirmationService service = buildService(activityLog, requestStore);

        Finding finding = new Finding("k", IssueType.FIREBASE_MISCONFIGURATION, "app.example.com", Severity.HIGH,
                Confidence.TENTATIVE, Status.POTENTIAL, OwaspRef.FIREBASE_MISCONFIG, "rationale", "remediation",
                List.of(Evidence.of(id, Evidence.Source.RESPONSE, 0, "snippet", null)));

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty());
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.message().contains("projectId")));
    }

    private ActiveConfirmationService buildService(ActivityLog activityLog, RequestStore requestStore) {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);
        SqliDetector sqliDetector = new SqliDetector(bypassEngine, activityLog);
        XssDetector xssDetector = new XssDetector(bypassEngine, activityLog);
        OastConfirmedDetector oastConfirmedDetector = new OastConfirmedDetector(bypassEngine, new OastCorrelator(), activityLog, "oast.pro");
        MassAssignmentDetector massAssignmentDetector = new MassAssignmentDetector(activityLog);
        FirebaseDetector firebaseDetector = new FirebaseDetector(activityLog);
        // firebaseSenderFactory stays null — the "no projectId" branch returns before it would be used.
        return new ActiveConfirmationService(requestStore, null, null, null, null, sqliDetector, xssDetector,
                oastConfirmedDetector, massAssignmentDetector, firebaseDetector, null, null, activityLog);
    }
}
