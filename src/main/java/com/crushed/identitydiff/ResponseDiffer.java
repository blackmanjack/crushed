package com.crushed.identitydiff;

/**
 * Compares an original (owner-identity) response against a replayed (alternate-identity) response.
 * A "same access" verdict means the alternate identity got a response indistinguishable in shape
 * from the original — i.e. it was NOT denied — which is the signal for BOLA/IDOR/privilege escalation.
 */
public final class ResponseDiffer {

    private static final double BODY_LENGTH_SIMILARITY_THRESHOLD = 0.85;

    public DiffVerdict compare(ReplayResult original, ReplayResult replayed) {
        if (replayed.networkError()) {
            return DiffVerdict.INCONCLUSIVE;
        }

        boolean deniedByStatus = isDenialStatus(replayed.statusCode()) && !isDenialStatus(original.statusCode());
        if (deniedByStatus) {
            return DiffVerdict.PROPERLY_DENIED;
        }

        boolean sameStatusClass = statusClass(original.statusCode()) == statusClass(replayed.statusCode());
        boolean similarBodyLength = similarLength(original.body(), replayed.body());

        if (sameStatusClass && similarBodyLength && isDenialStatus(replayed.statusCode()) == isDenialStatus(original.statusCode())) {
            if (!isDenialStatus(replayed.statusCode())) {
                return DiffVerdict.SAME_ACCESS;
            }
        }
        return DiffVerdict.PROPERLY_DENIED;
    }

    private boolean isDenialStatus(int status) {
        return status == 401 || status == 403 || status == 404;
    }

    private int statusClass(int status) {
        return status / 100;
    }

    private boolean similarLength(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        if (a.isEmpty() && b.isEmpty()) return true;
        int longer = Math.max(a.length(), b.length());
        int shorter = Math.min(a.length(), b.length());
        if (longer == 0) return true;
        return ((double) shorter / longer) >= BODY_LENGTH_SIMILARITY_THRESHOLD;
    }

    public enum DiffVerdict {
        SAME_ACCESS,       // alternate identity got equivalent access -> BOLA/IDOR candidate, CONFIRMED
        PROPERLY_DENIED,   // alternate identity was denied -> no finding
        INCONCLUSIVE       // network error etc. -> no finding, log only
    }
}
