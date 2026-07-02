package com.crushed.core;

import com.crushed.model.IssueType;
import com.crushed.model.Severity;

/** Maps an issue type to a default Severity (impact-driven baseline; can be refined later by chaining). */
public final class SeverityMatrix {

    private SeverityMatrix() {
    }

    public static Severity severityFor(IssueType issueType) {
        return switch (issueType) {
            case MASS_ASSIGNMENT, RCE, SQL_INJECTION, SSTI, SSRF, IDOR_BOLA, XXE, AI_SESSION_MISCONFIGURATION, PATH_TRAVERSAL ->
                    Severity.HIGH;
            case FIREBASE_MISCONFIGURATION, DOM_XSS, REFLECTED_XSS, JWT_WEAKNESS, CSRF, CRLF_INJECTION, OAUTH_MISCONFIGURATION ->
                    Severity.MEDIUM;
            case CORS_MISCONFIGURATION, OPEN_REDIRECT, UNICODE_NORMALIZATION, RACE_CONDITION_CANDIDATE ->
                    Severity.LOW;
            case GRAPHQL_INTROSPECTION, SENSITIVE_INFO_DISCLOSURE, REFLECTED_INPUT ->
                    Severity.INFO;
        };
    }
}
