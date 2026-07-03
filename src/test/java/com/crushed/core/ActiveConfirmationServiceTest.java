package com.crushed.core;

import com.crushed.detectors.BlockDetector;
import com.crushed.detectors.FirebaseDetector;
import com.crushed.detectors.MassAssignmentDetector;
import com.crushed.detectors.OastConfirmedDetector;
import com.crushed.detectors.PayloadVariantGenerator;
import com.crushed.detectors.SqliDetector;
import com.crushed.detectors.WafBypassEngine;
import com.crushed.detectors.XssDetector;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.oast.OastCorrelator;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ActiveConfirmationServiceTest {

    @Test
    void reportsErrorWhenNoStoredRequestExists() {
        RequestStore requestStore = new RequestStore();
        ActivityLog activityLog = new ActivityLog();
        ActiveConfirmationService service = buildService(requestStore, activityLog, null);

        Finding finding = findingWithEvidence(IssueType.SQL_INJECTION, 999, "q");

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty());
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.level() == ActivityLog.Level.ERROR));
    }

    @Test
    void reportsInfoWhenNoParameterOnFinding() {
        RequestStore requestStore = new RequestStore();
        int id = requestStore.record(null, null);
        ActivityLog activityLog = new ActivityLog();
        ActiveConfirmationService service = buildService(requestStore, activityLog, null);

        Finding finding = new Finding("k", IssueType.SQL_INJECTION, "endpoint", Severity.HIGH, Confidence.TENTATIVE,
                Status.POTENTIAL, OwaspRef.SQLI, "rationale", "remediation",
                List.of(Evidence.of(id, Evidence.Source.REQUEST, 0, "snippet", null)));

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty());
    }

    @Test
    void reportsInfoForUnwiredIssueType() {
        RequestStore requestStore = new RequestStore();
        int id = requestStore.record(null, null);
        ActivityLog activityLog = new ActivityLog();
        ActiveConfirmationService service = buildService(requestStore, activityLog, null);

        Finding finding = findingWithEvidenceAndId(IssueType.CSRF, id, "role");

        List<Finding> result = service.confirm(finding);

        assertTrue(result.isEmpty());
    }

    private ActiveConfirmationService buildService(RequestStore requestStore, ActivityLog activityLog, Object unused) {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);
        SqliDetector sqliDetector = new SqliDetector(bypassEngine, activityLog);
        XssDetector xssDetector = new XssDetector(bypassEngine, activityLog);
        OastConfirmedDetector oastConfirmedDetector = new OastConfirmedDetector(bypassEngine, new OastCorrelator(), activityLog, "oast.pro");
        MassAssignmentDetector massAssignmentDetector = new MassAssignmentDetector(activityLog);
        FirebaseDetector firebaseDetector = new FirebaseDetector(activityLog);
        // ParameterSubstitutingSender/BodySubstitutingSender/MassAssignmentSender/FirebaseSender
        // need a real MontoyaApi to build; these tests only exercise paths that fail before any
        // of them would be invoked (missing store entry / missing param / unwired type).
        return new ActiveConfirmationService(requestStore, null, null, null, null, sqliDetector, xssDetector,
                oastConfirmedDetector, massAssignmentDetector, firebaseDetector, null, null, null, null, activityLog);
    }

    private Finding findingWithEvidence(IssueType issueType, int historyId, String param) {
        return new Finding("k", issueType, "endpoint", Severity.HIGH, Confidence.TENTATIVE, Status.POTENTIAL,
                issueType.defaultOwaspRef(), "rationale", "remediation",
                List.of(Evidence.of(historyId, Evidence.Source.REQUEST, 0, "snippet", param)));
    }

    private Finding findingWithEvidenceAndId(IssueType issueType, int historyId, String param) {
        return findingWithEvidence(issueType, historyId, param);
    }
}
