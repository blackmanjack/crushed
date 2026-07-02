# crushed

A Burp Suite extension that triages HTTP/WebSocket traffic like a senior penetration tester,
keeps a growing "second-brain" notes file per host, and (optionally) actively confirms findings —
built to work on **Burp Suite Community**, which has no built-in Scanner.

Every hypothesis is mapped to OWASP Top 10 / API Security Top 10 / WSTG / CWE, findings are
split into **Confirmed** vs **Potential**, and every finding traces back to the exact
`Req #<id>` and byte offset it came from.

## What it does

**Passive (always on, no traffic sent):**
- Reads existing Proxy history on load, then analyzes new in-scope traffic as it arrives.
- 18 passive analyzers: IDOR/BOLA heuristics, CORS misconfig, JWT weaknesses, GraphQL
  introspection, CSRF, Unicode/homoglyph bypass, mass assignment, Firebase misconfig, XXE/SSRF/
  SQLi/XSS/SSTI/RCE surface detection, multi-language source analysis (JS/TS/HTML/ASPX/JSP/PHP —
  DOM sinks, sources, hardcoded secrets), WebSocket frame analysis, and **multi-account session
  diffing** (if you browse as two logged-in accounts, it flags endpoints where both sessions get
  indistinguishable responses — direct evidence of missing per-user authorization).
- Endpoint registry that keeps growing across the session (and persists), with every endpoint's
  params, auth scheme, and touching request IDs.

**Active (opt-in, OFF by default — see Settings tab):**
- Identity Diff Engine (Autorize-style replay with a second identity's cookie/token).
- SQLi (boolean-based), reflected/DOM XSS (canary), SSRF/XXE/RCE (OAST-confirmed via Interactsh).
- A shared WAF/filter-bypass engine that auto-retries blocked payloads with generic evasion
  techniques (case variation, encoding, bracket-notation, null-byte, etc.) across every class.
- AI analysis (Claude) — sends a **redacted** summary of findings for cross-request correlation.
- Yandex dorking recon — collects **unverified leads** only, never auto-fetched.

## Requirements

- **JDK 17+** (to build)
- **Burp Suite** (Community or Professional) — Community is the primary target since it lacks Scanner
- Internet access only if you turn on AI analysis, OAST, or Yandex recon (all OFF by default)

## Build

```bash
# Windows
gradlew.bat shadowJar

# macOS/Linux
./gradlew shadowJar
```

This produces `build/libs/crushed.jar`. If `gradlew`/`gradlew.bat` isn't executable or the wrapper
jar is missing, install Gradle 8.x yourself and run `gradle shadowJar` instead.

To run the test suite: `gradlew.bat test` (or `./gradlew test`).

## Install into Burp Suite

1. Open Burp Suite → **Extensions** tab → **Installed** sub-tab → **Add**.
2. Extension type: **Java**.
3. Extension file: browse to `build/libs/crushed.jar`.
4. Click **Next**, then **Close**. A new **crushed** tab appears in the main Burp window.
5. Check the **Output** panel in the extension details for `crushed loaded: N host(s)
   pre-loaded from history.` — this confirms it's running.

No native dependencies. The extension requires Burp's Montoya API (Burp 2023.12+); if your
Burp Suite version is older, update it first (Help → Check for updates, or download the latest
from PortSwigger).

## Using it

1. **Set your Target scope** in Burp as usual (Target tab → Scope). crushed only analyzes
   traffic matching this scope.
2. Browse the target application through Burp's Proxy. crushed picks up traffic automatically.
3. Open the **crushed** tab:
   - Left panel: list of hosts seen.
   - **Findings + Notes**: click a host to see its findings table and rendered Markdown notes.
     Right-click a finding for actions (send to Repeater, confirm actively, mark
     confirmed/false-positive/ignored).
   - **Activity / Errors**: live log of every analyzer error, blocked/bypassed active probe, and
     background-task failure — nothing fails silently.
   - **Recon (Yandex)**: optional dork-based recon (see Settings to enable first).
   - **Settings**: toggles for Active mode, Identity Diff, OAST, AI, Yandex, plus the Anthropic
     API key and Interactsh server fields.
4. Click **Export Notes (.md)** to write the current host's notes to `~/crushed-notes/<host>.md`.

### Turning on active features

Everything active is opt-in and gated behind **Active mode** in the Settings tab. Only enable
this against systems you're authorized to test.

- **Active mode** — master switch; unlocks Identity Diff and OAST toggles, and lets
  "Confirm Actively" on a finding actually send a request.
- **Identity Diff Engine** — register a second identity (cookie/bearer token) to replay
  requests as a different user and prove BOLA/IDOR by diffing responses. *(Currently wired at
  the engine level; UI for registering multiple identities is not yet exposed — see Limitations.)*
- **OAST (Interactsh)** — used automatically by SSRF/XXE/RCE confirmation once Active mode is on.
- **AI analysis** — paste an Anthropic API key; "Analyze Host with AI" sends a **redacted**
  findings summary (never raw traffic) to Claude for cross-request correlation.
- **Yandex dorking** — enter a target domain in the Recon tab and click "Run Recon". Results are
  unverified leads only — nothing is auto-fetched; validate manually before treating a lead as a
  finding.

## Known limitations

- No headless browser — DOM XSS confirmation is pattern-matching (sink+source correlation or
  canary reflection), not real JS execution.
- No crawler — crushed only sees traffic that passes through Burp's Proxy.
- Active confirmation is wired for SQLi, XSS, SSRF, XXE, and RCE. Mass Assignment, Firebase,
  DOM-XSS-chain (backURL), and AI-session misconfiguration have passive detection but no active
  confirmation path yet.
- Identity Diff Engine has no identity-registration UI yet; it's usable programmatically but not
  from the Settings tab.
