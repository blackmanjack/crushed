package com.crushed.model;

/** Burp-Pro-style catalog of standard issue names, descriptions, and default OWASP mapping. */
public enum IssueType {
    MASS_ASSIGNMENT("Mass assignment / identity drift", OwaspRef.MASS_ASSIGNMENT),
    FIREBASE_MISCONFIGURATION("Firebase misconfiguration", OwaspRef.FIREBASE_MISCONFIG),
    XXE("XML external entity injection", OwaspRef.XXE),
    DOM_XSS("Cross-site scripting (DOM-based)", OwaspRef.DOM_XSS),
    OPEN_REDIRECT("Open redirect", OwaspRef.OPEN_REDIRECT),
    AI_SESSION_MISCONFIGURATION("AI session misconfiguration", OwaspRef.AI_SESSION_MISCONFIG),
    IDOR_BOLA("Broken object level authorization (IDOR)", OwaspRef.IDOR_BOLA),
    SQL_INJECTION("SQL injection", OwaspRef.SQLI),
    RCE("Command / remote code execution", OwaspRef.RCE),
    REFLECTED_XSS("Cross-site scripting (reflected)", OwaspRef.XSS),
    SSTI("Server-side template injection", OwaspRef.SSTI),
    SSRF("Server-side request forgery", OwaspRef.SSRF),
    CORS_MISCONFIGURATION("CORS misconfiguration", OwaspRef.CORS_MISCONFIG),
    JWT_WEAKNESS("JWT weakness", OwaspRef.JWT_WEAKNESS),
    GRAPHQL_INTROSPECTION("GraphQL introspection enabled", OwaspRef.GRAPHQL_INTROSPECTION),
    CSRF("Cross-site request forgery", OwaspRef.CSRF),
    UNICODE_NORMALIZATION("Unicode normalization / homoglyph bypass", OwaspRef.UNICODE_NORMALIZATION),
    SENSITIVE_INFO_DISCLOSURE("Sensitive information disclosure", OwaspRef.SENSITIVE_INFO_DISCLOSURE),
    RACE_CONDITION_CANDIDATE("Business logic / race condition candidate", OwaspRef.RACE_CONDITION),
    REFLECTED_INPUT("Reflected user input", OwaspRef.REFLECTED_INPUT),
    PATH_TRAVERSAL("Path traversal", OwaspRef.PATH_TRAVERSAL),
    CRLF_INJECTION("CRLF injection / HTTP response splitting", OwaspRef.CRLF_INJECTION),
    OAUTH_MISCONFIGURATION("OAuth/OIDC misconfiguration", OwaspRef.OAUTH_MISCONFIG);

    private final String displayName;
    private final OwaspRef defaultOwaspRef;

    IssueType(String displayName, OwaspRef defaultOwaspRef) {
        this.displayName = displayName;
        this.defaultOwaspRef = defaultOwaspRef;
    }

    public String displayName() {
        return displayName;
    }

    public OwaspRef defaultOwaspRef() {
        return defaultOwaspRef;
    }
}
