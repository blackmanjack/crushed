package com.crushed.recon;

/** An unverified URL discovered via recon (e.g. Yandex dorking). Never auto-fetched. */
public record Lead(String url, Bucket bucket, String source, boolean verified) {

    public enum Bucket { API, JAVASCRIPT, AUTH_ADMIN, ENVIRONMENTS, FILES, DOCUMENTS, OTHER }

    public static Lead unverified(String url, Bucket bucket, String source) {
        return new Lead(url, bucket, source, false);
    }
}
