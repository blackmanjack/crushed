package com.crushed;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.crushed.ai.AiAnalyst;
import com.crushed.ai.ClaudeClient;
import com.crushed.ai.Redactor;
import com.crushed.analyzers.Analyzer;
import com.crushed.analyzers.impl.*;
import com.crushed.core.ActiveConfirmationService;
import com.crushed.core.AnalysisPipeline;
import com.crushed.core.BackupFileProbe;
import com.crushed.core.BodySubstitutingSender;
import com.crushed.core.CrawlEngine;
import com.crushed.core.EndpointRegistry;
import com.crushed.core.HistoryIngestor;
import com.crushed.core.FirebaseSender;
import com.crushed.core.ForbiddenBypassSender;
import com.crushed.core.LinkHarvester;
import com.crushed.core.LiveTaskManager;
import com.crushed.core.MassAssignmentSender;
import com.crushed.core.MontoyaRequestSender;
import com.crushed.core.ParameterSubstitutingSender;
import com.crushed.core.RequestFingerprint;
import com.crushed.core.ReplayableRequestFactory;
import com.crushed.core.RequestStore;
import com.crushed.core.ScopeGate;
import com.crushed.core.SessionColorAssigner;
import com.crushed.core.TriagePersistenceBridge;
import com.crushed.core.TriageStore;
import com.crushed.core.WstgCatalog;
import com.crushed.core.WstgChecklistPersistenceBridge;
import com.crushed.core.WstgChecklistStore;
import com.crushed.detectors.BlockDetector;
import com.crushed.detectors.CrlfInjectionDetector;
import com.crushed.detectors.FirebaseDetector;
import com.crushed.detectors.ForbiddenBypassDetector;
import com.crushed.detectors.MassAssignmentDetector;
import com.crushed.detectors.OastConfirmedDetector;
import com.crushed.detectors.PathTraversalDetector;
import com.crushed.detectors.PayloadVariantGenerator;
import com.crushed.detectors.SqliDetector;
import com.crushed.detectors.WafBypassEngine;
import com.crushed.detectors.XssDetector;
import com.crushed.identitydiff.Identity;
import com.crushed.identitydiff.IdentityRegistry;
import com.crushed.identitydiff.IdentityReplayEngine;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.identitydiff.ReplayableRequest;
import com.crushed.identitydiff.ResponseDiffer;
import com.crushed.oast.OastCorrelator;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.TriageState;
import com.crushed.recon.DorkQueryBuilder;
import com.crushed.recon.JdkHtmlFetcher;
import com.crushed.recon.Lead;
import com.crushed.recon.UrlClassifier;
import com.crushed.recon.YandexDorker;
import com.crushed.ui.ActivityLog;
import com.crushed.ui.CrushedTab;
import com.crushed.ui.FindingActionHandler;
import com.crushed.ui.SettingsPanel;

import java.util.List;

public final class CrushedExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("crushed");

        ScopeGate scopeGate = new ScopeGate(api);
        EndpointRegistry registry = new EndpointRegistry();
        ActivityLog activityLog = new ActivityLog();
        IdentityRegistry identityRegistry = new IdentityRegistry();
        SettingsPanel settingsPanel = new SettingsPanel(identityRegistry);
        LiveTaskManager liveTaskManager = new LiveTaskManager(scopeGate::isInScope);

        // ---- MVP: passive pipeline (Iterasi 1) ----
        List<Analyzer> analyzers = List.of(
                new FingerprintAnalyzer(),
                new AuthAnalyzer(),
                new CorsAnalyzer(),
                new JwtAnalyzer(),
                new GraphQlAnalyzer(),
                new CsrfAnalyzer(),
                new UnicodeNormalizationAnalyzer(),
                new BusinessLogicAnalyzer(),
                new ContextAnalyzer(),
                new SourceAnalyzer(),
                new WebSocketAnalyzer(),
                new SqliAnalyzer(),
                new XssAnalyzer(),
                new SsrfAnalyzer(),
                new SstiAnalyzer(),
                new RceAnalyzer(),
                new XxeAnalyzer(),
                new SessionDiffAnalyzer(),
                new ReflectedInputAnalyzer(),
                new PathTraversalAnalyzer(),
                new CrlfInjectionAnalyzer(),
                new OAuthAnalyzer(),
                new CookieSecurityAnalyzer(),
                new SecurityHeaderAnalyzer(),
                new DeserializationAnalyzer(),
                new RequestSmugglingAnalyzer(),
                new PrototypePollutionAnalyzer(),
                new ForbiddenResponseAnalyzer()
        );

        RequestStore requestStore = new RequestStore();
        SessionColorAssigner sessionColorAssigner = new SessionColorAssigner();

        TriageStore triageStore = new TriageStore();
        TriagePersistenceBridge triagePersistenceBridge = new TriagePersistenceBridge(api.persistence().extensionData(), activityLog);
        triagePersistenceBridge.loadInto(triageStore);

        WstgCatalog wstgCatalog = new WstgCatalog();
        WstgChecklistStore wstgChecklistStore = new WstgChecklistStore();
        WstgChecklistPersistenceBridge wstgChecklistPersistenceBridge =
                new WstgChecklistPersistenceBridge(api.persistence().extensionData(), activityLog);
        wstgChecklistPersistenceBridge.loadInto(wstgChecklistStore);

        AnalysisPipeline pipeline = new AnalysisPipeline(registry, analyzers, api.logging(), activityLog, triageStore);
        HistoryIngestor ingestor = new HistoryIngestor(api, scopeGate, pipeline, requestStore,
                sessionColorAssigner, settingsPanel::isSessionColorCodingEnabled);

        // Read what's already in history before hooking new traffic.
        ingestor.ingestExistingHistory();

        // ---- Iterasi 2: active modules, all default OFF via SettingsPanel ----
        // These are constructed eagerly (cheap, no network) but every send path is gated on
        // settingsPanel.isActiveModeEnabled() inside MontoyaRequestSender, so nothing leaves
        // the extension unless the user explicitly turns Active mode on. Wiring these into a
        // per-finding "confirm actively" UI action is the next slice of work, not yet exposed.
        MontoyaRequestSender requestSender = new MontoyaRequestSender(api, scopeGate, settingsPanel::isActiveModeEnabled, activityLog);
        WafBypassEngine wafBypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);
        OastCorrelator oastCorrelator = new OastCorrelator();
        IdentityReplayEngine identityReplayEngine = new IdentityReplayEngine(requestSender, new ResponseDiffer(), activityLog);
        SqliDetector sqliDetector = new SqliDetector(wafBypassEngine, activityLog);
        XssDetector xssDetector = new XssDetector(wafBypassEngine, activityLog);
        OastConfirmedDetector oastConfirmedDetector = new OastConfirmedDetector(
                wafBypassEngine, oastCorrelator, activityLog, settingsPanel.oastServer());
        ParameterSubstitutingSender paramSender = new ParameterSubstitutingSender(api, scopeGate, settingsPanel::isActiveModeEnabled, activityLog);
        BodySubstitutingSender bodySender = new BodySubstitutingSender(api, scopeGate, settingsPanel::isActiveModeEnabled, activityLog);
        MassAssignmentSender massAssignmentSender = new MassAssignmentSender(api, scopeGate, settingsPanel::isActiveModeEnabled);
        MassAssignmentDetector massAssignmentDetector = new MassAssignmentDetector(activityLog);
        FirebaseSender firebaseSender = new FirebaseSender(api, settingsPanel::isActiveModeEnabled, activityLog);
        FirebaseDetector firebaseDetector = new FirebaseDetector(activityLog);
        PathTraversalDetector pathTraversalDetector = new PathTraversalDetector(wafBypassEngine, activityLog);
        CrlfInjectionDetector crlfInjectionDetector = new CrlfInjectionDetector(activityLog);
        ForbiddenBypassSender forbiddenBypassSender = new ForbiddenBypassSender(api, scopeGate, settingsPanel::isActiveModeEnabled, activityLog);
        ForbiddenBypassDetector forbiddenBypassDetector = new ForbiddenBypassDetector(activityLog);
        ActiveConfirmationService activeConfirmationService = new ActiveConfirmationService(
                requestStore, paramSender, bodySender, massAssignmentSender, firebaseSender, sqliDetector, xssDetector,
                oastConfirmedDetector, massAssignmentDetector, firebaseDetector, pathTraversalDetector,
                crlfInjectionDetector, forbiddenBypassSender, forbiddenBypassDetector, activityLog);
        CrawlEngine crawlEngine = new CrawlEngine(api, scopeGate, ingestor, new LinkHarvester(),
                settingsPanel::isActiveModeEnabled, settingsPanel::isCrawlingEnabled,
                settingsPanel::crawlMaxRequests, settingsPanel::crawlMaxDepth, settingsPanel::crawlDelayMs, activityLog);
        BackupFileProbe backupFileProbe = new BackupFileProbe(scopeGate, crawlEngine, settingsPanel::isActiveModeEnabled, activityLog);
        java.util.Set<String> autoConfirmedDedupeKeys = java.util.concurrent.ConcurrentHashMap.newKeySet();

        // Generic Http handler (not Proxy-only) gated by LiveTaskManager — this is what unlocks
        // Repeater/Intruder-sourced traffic being analyzed, which Proxy-only ingestion never could.
        // Fresh installs get exactly today's behavior via LiveTaskManager's seeded default task
        // (Proxy tools, Suite scope, PASSIVE_ANALYSIS, no dedup).
        try {
            api.http().registerHttpHandler(new burp.api.montoya.http.handler.HttpHandler() {
                @Override
                public burp.api.montoya.http.handler.RequestToBeSentAction handleHttpRequestToBeSent(
                        burp.api.montoya.http.handler.HttpRequestToBeSent request) {
                    return burp.api.montoya.http.handler.RequestToBeSentAction.continueWith(request);
                }

                @Override
                public burp.api.montoya.http.handler.ResponseReceivedAction handleHttpResponseReceived(
                        burp.api.montoya.http.handler.HttpResponseReceived response) {
                    try {
                        var tool = response.toolSource().toolType();
                        var request = response.initiatingRequest();
                        String url = request.url();
                        if (liveTaskManager.shouldIngest(tool, url)) {
                            String endpointKey = (request.httpService() != null ? request.httpService().host() : "") + " "
                                    + request.method() + " " + RequestFingerprint.normalizePathTemplate(request.path());
                            if (liveTaskManager.shouldProceedWithDedup(tool, url, endpointKey)) {
                                ingestor.ingestFetched(request, response, response.annotations());
                                if (liveTaskManager.shouldAutoConfirm(tool, url)) {
                                    HostNotes hostNotes = registry.hostNotesFor(request.httpService() != null ? request.httpService().host() : "");
                                    for (Finding finding : hostNotes.potentialFindings()) {
                                        if (!finding.endpointKey().equals(endpointKey)) continue;
                                        if (!autoConfirmedDedupeKeys.add(finding.dedupeKey())) continue;
                                        try {
                                            for (Finding confirmed : activeConfirmationService.confirm(finding)) {
                                                hostNotes.addOrMergeFinding(confirmed);
                                            }
                                        } catch (Exception e) {
                                            activityLog.error("LiveTask", -1, "Auto-confirm failed for " + finding.dedupeKey() + ": " + e);
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        activityLog.error("CrushedExtension", -1, "handleHttpResponseReceived failed: " + e);
                    }
                    return burp.api.montoya.http.handler.ResponseReceivedAction.continueWith(response);
                }
            });
        } catch (Exception e) {
            api.logging().logToError("Failed to register HTTP handler: " + e);
            activityLog.error("CrushedExtension", -1, "Failed to register HTTP handler: " + e);
        }

        FindingActionHandler actionHandler = new FindingActionHandler() {
            @Override
            public void sendToRepeater(int historyId) {
                RequestStore.Stored stored = requestStore.get(historyId);
                if (stored == null) {
                    activityLog.error("CrushedTab", historyId, "No stored request found for this id (may predate extension load or have been evicted).");
                    return;
                }
                try {
                    api.repeater().sendToRepeater(stored.request());
                } catch (Exception e) {
                    activityLog.error("CrushedTab", historyId, "Send to Repeater failed: " + e);
                }
            }

            @Override
            public List<Finding> confirmActively(Finding finding) {
                try {
                    return activeConfirmationService.confirm(finding);
                } catch (Exception e) {
                    activityLog.error("ActiveConfirmationService", -1, "confirmActively failed: " + e);
                    return List.of();
                }
            }

            @Override
            public String analyzeWithAi(HostNotes hostNotes) {
                if (!settingsPanel.isAiEnabled()) return null;
                String apiKey = settingsPanel.apiKey();
                if (apiKey == null || apiKey.isBlank()) {
                    activityLog.error("AiAnalyst", -1, "AI analysis is enabled but no API key is set.");
                    return null;
                }
                AiAnalyst analyst = new AiAnalyst(new ClaudeClient(apiKey), new Redactor(), activityLog);
                return analyst.analyze(hostNotes);
            }

            @Override
            public List<Lead> runYandexRecon(String targetDomain) {
                if (!settingsPanel.isYandexEnabled()) {
                    activityLog.error("YandexDorker", -1, "Yandex dorking is disabled in Settings.");
                    return List.of();
                }
                YandexDorker dorker = new YandexDorker(new DorkQueryBuilder(), new UrlClassifier(),
                        new JdkHtmlFetcher(), activityLog);
                return dorker.run(targetDomain, url -> scopeGate.isInScope(url));
            }

            @Override
            public List<Finding> runIdentityDiff(Finding finding) {
                if (!settingsPanel.isActiveModeEnabled() || !settingsPanel.isIdentityDiffEnabled()) {
                    activityLog.error("IdentityReplayEngine", -1, "Identity Diff is disabled (enable Active mode + Identity Diff in Settings).");
                    return List.of();
                }
                List<Identity> identities = identityRegistry.all();
                if (identities.isEmpty()) {
                    activityLog.error("IdentityReplayEngine", -1, "No identities registered — add at least one in Settings.");
                    return List.of();
                }
                if (finding.evidence().isEmpty()) return List.of();

                int historyId = finding.evidence().get(0).historyId();
                RequestStore.Stored stored = requestStore.get(historyId);
                if (stored == null || stored.request() == null) {
                    activityLog.error("IdentityReplayEngine", historyId, "No stored original request for this finding.");
                    return List.of();
                }

                try {
                    ReplayableRequest original = ReplayableRequestFactory.from(historyId, stored.request());
                    ReplayResult originalResult = ReplayableRequestFactory.originalResultFrom(stored.response());

                    List<Finding> confirmed = new java.util.ArrayList<>();
                    for (Identity identity : identities) {
                        confirmed.addAll(identityReplayEngine.replayWithIdentity(original, originalResult, identity));
                    }
                    return confirmed;
                } catch (Exception e) {
                    activityLog.error("IdentityReplayEngine", historyId, "runIdentityDiff failed: " + e);
                    return List.of();
                }
            }

            @Override
            public void setTriageState(Finding finding, TriageState state) {
                finding.setTriageState(state);
                triageStore.put(finding.dedupeKey(), state);
                triagePersistenceBridge.persist(finding.dedupeKey(), state);
            }

            @Override
            public void fillMissingSiteMapResponses() {
                try {
                    crawlEngine.fillMissingSiteMapResponses();
                } catch (Exception e) {
                    activityLog.error("CrawlEngine", -1, "fillMissingSiteMapResponses failed: " + e);
                }
            }

            @Override
            public void startCrawl(String seedUrl) {
                try {
                    crawlEngine.crawl(seedUrl);
                } catch (Exception e) {
                    activityLog.error("CrawlEngine", -1, "startCrawl failed: " + e);
                }
            }

            @Override
            public List<Finding> probeBackupFiles(String baseUrl) {
                try {
                    return backupFileProbe.probeHost(baseUrl);
                } catch (Exception e) {
                    activityLog.error("BackupFileProbe", -1, "probeBackupFiles failed: " + e);
                    return List.of();
                }
            }
        };

        CrushedTab tab = new CrushedTab(registry, activityLog, settingsPanel, actionHandler,
                wstgCatalog, wstgChecklistStore, wstgChecklistPersistenceBridge, liveTaskManager);
        api.userInterface().registerSuiteTab("crushed", tab.component());

        api.logging().logToOutput("crushed loaded: " + registry.hostCount() + " host(s) pre-loaded from history. " +
                "Active mode is OFF by default; enable it in the Settings tab to use identity-diff/OAST/active detectors.");
    }
}
