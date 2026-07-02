package com.crushed.recon;

import com.crushed.ui.ActivityLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scoped Yandex dork recon loop: Recon -> Filter (in-scope) -> Dedupe -> Classify, mirroring
 * the reference yadexloop.sh pipeline. Results are always unverified Leads — never auto-fetched
 * or auto-added to the analysis pipeline; a human must send a lead to Repeater/Proxy before it's
 * analyzed. The HTML fetch step is injected so this class is unit-testable without a live
 * Yandex request.
 */
public final class YandexDorker {

    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\"'<>\\s]+");

    private final DorkQueryBuilder queryBuilder;
    private final UrlClassifier classifier;
    private final Function<String, String> htmlFetcher;
    private final ActivityLog activityLog;

    public YandexDorker(DorkQueryBuilder queryBuilder, UrlClassifier classifier,
                         Function<String, String> htmlFetcher, ActivityLog activityLog) {
        this.queryBuilder = queryBuilder;
        this.classifier = classifier;
        this.htmlFetcher = htmlFetcher;
        this.activityLog = activityLog;
    }

    /** @param inScope predicate deciding whether a discovered URL belongs to the target's scope */
    public List<Lead> run(String targetDomain, Predicate<String> inScope) {
        Set<String> seenUrls = new LinkedHashSet<>();
        List<Lead> leads = new ArrayList<>();

        for (String query : queryBuilder.buildQueries(targetDomain)) {
            String html;
            try {
                html = htmlFetcher.apply(query);
            } catch (Exception e) {
                activityLog.error("YandexDorker", -1, "Dork query failed for '" + query + "': " + e);
                continue;
            }
            if (html == null) continue;

            Matcher matcher = URL_PATTERN.matcher(html);
            while (matcher.find()) {
                String url = stripTrailingJunk(matcher.group());
                if (!url.contains(targetDomain)) continue;
                if (!inScope.test(url)) continue;
                if (!seenUrls.add(url)) continue;

                Lead.Bucket bucket = classifier.classify(url);
                leads.add(Lead.unverified(url, bucket, "YANDEX"));
            }
        }

        activityLog.info("YandexDorker", -1, "Recon complete for " + targetDomain + ": " + leads.size() + " unverified lead(s).");
        return leads;
    }

    private String stripTrailingJunk(String url) {
        return url.replaceAll("[),;\"'>]+$", "");
    }
}
