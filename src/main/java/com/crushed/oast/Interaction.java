package com.crushed.oast;

import java.time.Instant;

/** A single out-of-band interaction reported by the OAST server (DNS/HTTP/SMTP callback). */
public record Interaction(
        String correlationId,
        String protocol,
        String remoteAddress,
        Instant timestamp,
        String rawDetails
) {
}
