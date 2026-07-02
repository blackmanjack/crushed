package com.crushed.recon;

import java.util.regex.Pattern;

/** Classifies a discovered URL into a bucket, mirroring the grep-based buckets from the
 *  reference yadexloop.sh script (api/javascript/auth_admin/environments/files/documents). */
public final class UrlClassifier {

    private static final Pattern API = Pattern.compile("(?i)/api/|graphql|swagger|openapi|redoc");
    private static final Pattern JAVASCRIPT = Pattern.compile("(?i)_next|\\.js(\\?|$)|chunk|webpack|static");
    private static final Pattern AUTH_ADMIN = Pattern.compile("(?i)admin|login|dashboard|signin|auth");
    private static final Pattern ENVIRONMENTS = Pattern.compile("(?i)staging|dev|test|beta|internal");
    private static final Pattern FILES = Pattern.compile("(?i)\\.json|\\.xml|\\.txt|\\.log|\\.env");
    private static final Pattern DOCUMENTS = Pattern.compile("(?i)\\.pdf|\\.docx?|\\.xlsx?|\\.csv");

    public Lead.Bucket classify(String url) {
        if (API.matcher(url).find()) return Lead.Bucket.API;
        if (JAVASCRIPT.matcher(url).find()) return Lead.Bucket.JAVASCRIPT;
        if (AUTH_ADMIN.matcher(url).find()) return Lead.Bucket.AUTH_ADMIN;
        if (ENVIRONMENTS.matcher(url).find()) return Lead.Bucket.ENVIRONMENTS;
        if (FILES.matcher(url).find()) return Lead.Bucket.FILES;
        if (DOCUMENTS.matcher(url).find()) return Lead.Bucket.DOCUMENTS;
        return Lead.Bucket.OTHER;
    }
}
