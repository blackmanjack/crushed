package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.regex.Pattern;

public final class SqliAnalyzer implements Analyzer {

    private static final Pattern[] DB_ERROR_SIGNATURES = {
            Pattern.compile("(?i)you have an error in your sql syntax"),
            Pattern.compile("(?i)unclosed quotation mark after the character string"),
            Pattern.compile("(?i)pg_query\\(\\)|PostgreSQL.*ERROR"),
            Pattern.compile("(?i)ORA-\\d{5}"),
            Pattern.compile("(?i)SQLite3?::")
    };

    @Override
    public String name() {
        return "SqliAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String body = context.responseBody();
        if (body == null || body.isEmpty()) return List.of();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        for (Pattern p : DB_ERROR_SIGNATURES) {
            var m = p.matcher(body);
            if (m.find()) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, m.start(), m.group(), null);
                return List.of(new Signal(IssueType.SQL_INJECTION, endpointKey, Confidence.FIRM,
                        "Response contains a database error signature, suggesting unsanitized input reaches a SQL query.",
                        evidence));
            }
        }
        return List.of();
    }
}
