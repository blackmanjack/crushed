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

class ActiveConfirmationServiceXxeRceTest {

    @Test
    void xxeRoutesToBodySubstitutionAndRegistersOastProbe() {
        RequestStore requestStore = new RequestStore();
        int id = requestStore.record(null, null);
        ActivityLog activityLog = new ActivityLog();
        OastCorrelator correlator = new OastCorrelator();

        ActiveConfirmationService service = buildService(requestStore, activityLog, correlator);

        Finding finding = new Finding("k", IssueType.XXE, "endpoint", Severity.HIGH, Confidence.TENTATIVE,
                Status.POTENTIAL, OwaspRef.XXE, "rationale", "remediation",
                List.of(Evidence.of(id, Evidence.Source.REQUEST, 0, "snippet", null)));

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty(), "XXE confirms asynchronously; no immediate finding is returned");
        assertEquals(1, correlator.pendingCount(), "an OAST probe should have been registered for later correlation");
    }

    @Test
    void rceRoutesToBodySubstitutionEvenWithoutAParameterName() {
        RequestStore requestStore = new RequestStore();
        int id = requestStore.record(null, null);
        ActivityLog activityLog = new ActivityLog();
        OastCorrelator correlator = new OastCorrelator();

        ActiveConfirmationService service = buildService(requestStore, activityLog, correlator);

        Finding finding = new Finding("k", IssueType.RCE, "endpoint", Severity.HIGH, Confidence.TENTATIVE,
                Status.POTENTIAL, OwaspRef.RCE, "rationale", "remediation",
                List.of(Evidence.of(id, Evidence.Source.REQUEST, 0, "snippet", null)));

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty());
        assertEquals(1, correlator.pendingCount());
    }

    private ActiveConfirmationService buildService(RequestStore requestStore, ActivityLog activityLog, OastCorrelator correlator) {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);
        SqliDetector sqliDetector = new SqliDetector(bypassEngine, activityLog);
        XssDetector xssDetector = new XssDetector(bypassEngine, activityLog);
        OastConfirmedDetector oastConfirmedDetector = new OastConfirmedDetector(bypassEngine, correlator, activityLog, "oast.pro");
        // Active mode reports OFF so BodySubstitutingSender never dereferences the (null) MontoyaApi.
        BodySubstitutingSender bodySender = new BodySubstitutingSender(null, null, () -> false, activityLog);
        MassAssignmentDetector massAssignmentDetector = new MassAssignmentDetector(activityLog);
        FirebaseDetector firebaseDetector = new FirebaseDetector(activityLog);
        return new ActiveConfirmationService(requestStore, null, bodySender, null, null, sqliDetector, xssDetector,
                oastConfirmedDetector, massAssignmentDetector, firebaseDetector, null, null, activityLog);
    }
}
