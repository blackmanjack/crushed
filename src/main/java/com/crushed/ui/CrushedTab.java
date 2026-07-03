package com.crushed.ui;

import burp.api.montoya.core.ToolType;
import com.crushed.core.EndpointRegistry;
import com.crushed.core.LiveTaskManager;
import com.crushed.core.WstgCatalog;
import com.crushed.core.WstgChecklistPersistenceBridge;
import com.crushed.core.WstgChecklistStore;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.LiveTaskConfig;
import com.crushed.model.TriageState;
import com.crushed.model.WstgCoverageState;
import com.crushed.model.WstgTestCase;
import com.crushed.notes.MarkdownNoteBuilder;
import com.crushed.notes.NoteExporter;
import com.crushed.recon.Lead;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Main Swing tab: host list + findings table + notes viewer + Activity/Errors log + Settings. */
public final class CrushedTab {

    private final EndpointRegistry registry;
    private final ActivityLog activityLog;
    private final SettingsPanel settingsPanel;
    private final FindingActionHandler actionHandler;
    private final WstgCatalog wstgCatalog;
    private final WstgChecklistStore wstgChecklistStore;
    private final WstgChecklistPersistenceBridge wstgChecklistPersistenceBridge;
    private final LiveTaskManager liveTaskManager;
    private final MarkdownNoteBuilder noteBuilder = new MarkdownNoteBuilder();
    private final NoteExporter noteExporter = new NoteExporter();

    private final JPanel root;
    private final DefaultListModel<String> hostListModel = new DefaultListModel<>();
    private final FindingsTableModel findingsTableModel = new FindingsTableModel();
    private final JTable findingsTable = new JTable(findingsTableModel);
    private final JTextArea notesArea = new JTextArea();
    private final JTextArea activityArea = new JTextArea();
    private final LeadsTableModel leadsTableModel = new LeadsTableModel();
    private final JTextField reconDomainField = new JTextField(30);
    private final WstgTableModel wstgTableModel = new WstgTableModel();
    private final LiveTaskTableModel liveTaskTableModel = new LiveTaskTableModel();
    private volatile String selectedHost;

    public CrushedTab(EndpointRegistry registry, ActivityLog activityLog, SettingsPanel settingsPanel,
                       FindingActionHandler actionHandler, WstgCatalog wstgCatalog,
                       WstgChecklistStore wstgChecklistStore, WstgChecklistPersistenceBridge wstgChecklistPersistenceBridge,
                       LiveTaskManager liveTaskManager) {
        this.registry = registry;
        this.activityLog = activityLog;
        this.settingsPanel = settingsPanel;
        this.actionHandler = actionHandler;
        this.wstgCatalog = wstgCatalog;
        this.wstgChecklistStore = wstgChecklistStore;
        this.wstgChecklistPersistenceBridge = wstgChecklistPersistenceBridge;
        this.liveTaskManager = liveTaskManager;
        this.root = build();
    }

    public Component component() {
        return root;
    }

    private JPanel build() {
        JPanel panel = new JPanel(new BorderLayout());

        JList<String> hostList = new JList<>(hostListModel);
        hostList.addListSelectionListener(e -> {
            selectedHost = hostList.getSelectedValue();
            refreshForSelection();
        });
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshHostList());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(new JScrollPane(hostList), BorderLayout.CENTER);
        leftPanel.add(refreshButton, BorderLayout.SOUTH);

        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setComponentPopupMenu(buildFindingsContextMenu());
        SeverityCellRenderer severityCellRenderer = new SeverityCellRenderer();
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(severityCellRenderer);
        findingsTable.getColumnModel().getColumn(1).setCellRenderer(severityCellRenderer);
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = findingsTable.getSelectedRow();
            if (row < 0) {
                refreshForSelection();
                return;
            }
            int modelRow = findingsTable.convertRowIndexToModel(row);
            notesArea.setText(noteBuilder.renderFinding(findingsTableModel.findingAt(modelRow)));
            notesArea.setCaretPosition(0);
        });

        notesArea.setEditable(false);
        notesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        activityArea.setEditable(false);
        activityArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        JButton exportButton = new JButton("Export Notes (.md)");
        exportButton.addActionListener(e -> exportSelectedHost());

        JButton aiButton = new JButton("Analyze Host with AI");
        aiButton.addActionListener(e -> analyzeSelectedHostWithAi());

        JPanel notesButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        notesButtonRow.add(exportButton);
        notesButtonRow.add(aiButton);

        JPanel notesPanel = new JPanel(new BorderLayout());
        notesPanel.add(new JScrollPane(notesArea), BorderLayout.CENTER);
        notesPanel.add(notesButtonRow, BorderLayout.SOUTH);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable), notesPanel);
        rightSplit.setDividerLocation(220);

        JTabbedPane rightTabs = new JTabbedPane();
        rightTabs.addTab("Findings + Notes", rightSplit);
        rightTabs.addTab("Activity / Errors", new JScrollPane(activityArea));
        rightTabs.addTab("Recon (Yandex)", buildReconPanel());
        rightTabs.addTab("Crawl", buildCrawlPanel());
        rightTabs.addTab("WSTG Checklist", buildWstgChecklistPanel());
        rightTabs.addTab("Live Tasks", buildLiveTasksPanel());
        rightTabs.addTab("Settings", settingsPanel.component());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightTabs);
        split.setDividerLocation(220);
        panel.add(split, BorderLayout.CENTER);

        Timer refreshTimer = new Timer(2000, e -> refreshActivityLog());
        refreshTimer.start();

        refreshHostList();
        return panel;
    }

    private JPopupMenu buildFindingsContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send evidence to Repeater");
        sendToRepeater.addActionListener(e -> withSelectedFinding(finding -> {
            for (Evidence evidence : finding.evidence()) {
                actionHandler.sendToRepeater(evidence.historyId());
            }
        }));

        JMenuItem confirmActively = new JMenuItem("Confirm Actively (requires Active mode ON)");
        confirmActively.addActionListener(e -> withSelectedFinding(finding -> {
            if (!settingsPanel.isActiveModeEnabled()) {
                JOptionPane.showMessageDialog(root, "Active mode is OFF. Enable it in the Settings tab first.",
                        "Active mode disabled", JOptionPane.WARNING_MESSAGE);
                return;
            }
            List<Finding> confirmed = actionHandler.confirmActively(finding);
            if (selectedHost != null) {
                HostNotes hostNotes = registry.hostNotesFor(selectedHost);
                for (Finding f : confirmed) {
                    hostNotes.addOrMergeFinding(f);
                }
            }
            refreshForSelection();
        }));

        JMenuItem identityDiff = new JMenuItem("Run Identity Diff (replay as registered identities)");
        identityDiff.addActionListener(e -> withSelectedFinding(finding -> {
            if (!settingsPanel.isActiveModeEnabled() || !settingsPanel.isIdentityDiffEnabled()) {
                JOptionPane.showMessageDialog(root, "Enable both Active mode and Identity Diff Engine in the Settings tab first.",
                        "Identity Diff disabled", JOptionPane.WARNING_MESSAGE);
                return;
            }
            List<Finding> confirmed = actionHandler.runIdentityDiff(finding);
            if (selectedHost != null) {
                HostNotes hostNotes = registry.hostNotesFor(selectedHost);
                for (Finding f : confirmed) {
                    hostNotes.addOrMergeFinding(f);
                }
            }
            refreshForSelection();
        }));

        JMenuItem markConfirmed = new JMenuItem("Mark as Confirmed (manual)");
        markConfirmed.addActionListener(e -> withSelectedFinding(f -> setTriage(f, TriageState.CONFIRMED_MANUAL)));

        JMenuItem markFalsePositive = new JMenuItem("Mark as False Positive");
        markFalsePositive.addActionListener(e -> withSelectedFinding(f -> setTriage(f, TriageState.FALSE_POSITIVE)));

        JMenuItem markIgnored = new JMenuItem("Ignore");
        markIgnored.addActionListener(e -> withSelectedFinding(f -> setTriage(f, TriageState.IGNORED)));

        menu.add(sendToRepeater);
        menu.add(confirmActively);
        menu.add(identityDiff);
        menu.addSeparator();
        menu.add(markConfirmed);
        menu.add(markFalsePositive);
        menu.add(markIgnored);
        return menu;
    }

    private void setTriage(Finding finding, TriageState state) {
        actionHandler.setTriageState(finding, state);
        refreshForSelection();
    }

    private void withSelectedFinding(java.util.function.Consumer<Finding> action) {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = findingsTable.convertRowIndexToModel(row);
        action.accept(findingsTableModel.findingAt(modelRow));
    }

    private void exportSelectedHost() {
        if (selectedHost == null) return;
        try {
            HostNotes hostNotes = registry.hostNotesFor(selectedHost);
            Path exportDir = Path.of(System.getProperty("user.home"), "crushed-notes");
            noteExporter.exportMarkdown(hostNotes, exportDir);
            JOptionPane.showMessageDialog(root, "Exported to " + exportDir.resolve(selectedHost + ".md"));
        } catch (IOException e) {
            activityLog.error("CrushedTab", -1, "Export failed: " + e);
            JOptionPane.showMessageDialog(root, "Export failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void analyzeSelectedHostWithAi() {
        if (selectedHost == null) return;
        if (!settingsPanel.isAiEnabled()) {
            JOptionPane.showMessageDialog(root, "AI analysis is OFF. Enable it in the Settings tab and set an API key first.",
                    "AI analysis disabled", JOptionPane.WARNING_MESSAGE);
            return;
        }
        HostNotes hostNotes = registry.hostNotesFor(selectedHost);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return actionHandler.analyzeWithAi(hostNotes);
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result != null) {
                        notesArea.setText(notesArea.getText() + "\n\n" + result + "\n");
                    } else {
                        JOptionPane.showMessageDialog(root, "AI analysis failed — see Activity / Errors tab.",
                                "AI analysis failed", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    activityLog.error("CrushedTab", -1, "AI analysis task failed: " + e);
                }
            }
        }.execute();
    }

    private JPanel buildReconPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JButton runButton = new JButton("Run Recon");
        runButton.addActionListener(e -> runYandexRecon());

        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topRow.add(new JLabel("Target domain:"));
        topRow.add(reconDomainField);
        topRow.add(runButton);

        JTable leadsTable = new JTable(leadsTableModel);
        leadsTable.setAutoCreateRowSorter(true);

        panel.add(topRow, BorderLayout.NORTH);
        panel.add(new JScrollPane(leadsTable), BorderLayout.CENTER);
        return panel;
    }

    private void runYandexRecon() {
        if (!settingsPanel.isYandexEnabled()) {
            JOptionPane.showMessageDialog(root, "Yandex dorking is OFF. Enable it in the Settings tab first.",
                    "Yandex dorking disabled", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String domain = reconDomainField.getText().trim();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(root, "Enter a target domain first.", "Missing domain", JOptionPane.WARNING_MESSAGE);
            return;
        }
        new SwingWorker<List<Lead>, Void>() {
            @Override
            protected List<Lead> doInBackground() {
                return actionHandler.runYandexRecon(domain);
            }

            @Override
            protected void done() {
                try {
                    leadsTableModel.setLeads(get());
                } catch (Exception e) {
                    activityLog.error("CrushedTab", -1, "Yandex recon task failed: " + e);
                }
            }
        }.execute();
    }

    private JPanel buildCrawlPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JButton fillButton = new JButton("Fill Missing Site Map Responses");
        fillButton.addActionListener(e -> runCrawlAction(fillButton, actionHandler::fillMissingSiteMapResponses));

        JTextField seedUrlField = new JTextField(30);
        JButton crawlButton = new JButton("Start Crawl");
        crawlButton.addActionListener(e -> {
            String seedUrl = seedUrlField.getText().trim();
            if (seedUrl.isEmpty()) {
                JOptionPane.showMessageDialog(root, "Enter a seed URL first.", "Missing seed URL", JOptionPane.WARNING_MESSAGE);
                return;
            }
            runCrawlAction(crawlButton, () -> actionHandler.startCrawl(seedUrl));
        });

        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topRow.add(fillButton);

        JPanel seedRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        seedRow.add(new JLabel("Seed URL:"));
        seedRow.add(seedUrlField);
        seedRow.add(crawlButton);

        JTextField backupUrlField = new JTextField(30);
        JButton backupProbeButton = new JButton("Probe Backup/Sensitive Files");
        backupProbeButton.addActionListener(e -> {
            String baseUrl = backupUrlField.getText().trim();
            if (baseUrl.isEmpty()) {
                JOptionPane.showMessageDialog(root, "Enter a base URL first (e.g. https://app.example.com).",
                        "Missing base URL", JOptionPane.WARNING_MESSAGE);
                return;
            }
            backupProbeButton.setEnabled(false);
            new SwingWorker<List<Finding>, Void>() {
                @Override
                protected List<Finding> doInBackground() {
                    return actionHandler.probeBackupFiles(baseUrl);
                }

                @Override
                protected void done() {
                    backupProbeButton.setEnabled(true);
                    try {
                        List<Finding> found = get();
                        if (selectedHost != null) {
                            HostNotes hostNotes = registry.hostNotesFor(selectedHost);
                            for (Finding f : found) {
                                hostNotes.addOrMergeFinding(f);
                            }
                            refreshForSelection();
                        }
                    } catch (Exception ex) {
                        activityLog.error("CrushedTab", -1, "probeBackupFiles task failed: " + ex);
                    }
                }
            }.execute();
        });

        JPanel backupRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        backupRow.add(new JLabel("Base URL:"));
        backupRow.add(backupUrlField);
        backupRow.add(backupProbeButton);

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(topRow);
        north.add(seedRow);
        north.add(backupRow);
        north.add(new JLabel("  Requires Active mode + Crawling enabled in Settings. Progress appears in Activity / Errors."));

        panel.add(north, BorderLayout.NORTH);
        return panel;
    }

    private void runCrawlAction(JButton button, Runnable action) {
        button.setEnabled(false);
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                action.run();
                return null;
            }

            @Override
            protected void done() {
                button.setEnabled(true);
                if (selectedHost != null) {
                    refreshForSelection();
                }
            }
        }.execute();
    }

    private JPanel buildWstgChecklistPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        wstgTableModel.setRows(wstgCatalog.all());

        JTable wstgTable = new JTable(wstgTableModel);
        wstgTable.setAutoCreateRowSorter(true);
        JComboBox<WstgCoverageState> statusCombo = new JComboBox<>(WstgCoverageState.values());
        wstgTable.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(statusCombo));

        TableRowSorter<WstgTableModel> sorter = new TableRowSorter<>(wstgTableModel);
        wstgTable.setRowSorter(sorter);

        JTextField filterField = new JTextField(30);
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }

            private void applyFilter() {
                String text = filterField.getText().trim();
                sorter.setRowFilter(text.isEmpty() ? null : RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
            }
        });

        JButton refreshCoverageButton = new JButton("Refresh Auto-Coverage");
        refreshCoverageButton.addActionListener(e -> wstgTableModel.refreshCoverage(registry));

        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topRow.add(new JLabel("Filter:"));
        topRow.add(filterField);
        topRow.add(refreshCoverageButton);

        panel.add(topRow, BorderLayout.NORTH);
        panel.add(new JScrollPane(wstgTable), BorderLayout.CENTER);

        wstgTableModel.refreshCoverage(registry);
        return panel;
    }

    private final class WstgTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"WSTG ID", "Category", "Test Name", "Auto-Coverage", "Manual Status"};
        private List<WstgTestCase> rows = List.of();
        private final Map<String, Integer> autoCoverage = new HashMap<>();

        void setRows(List<WstgTestCase> newRows) {
            rows = newRows;
            fireTableDataChanged();
        }

        void refreshCoverage(EndpointRegistry registry) {
            autoCoverage.clear();
            for (Finding finding : registry.allFindingsAcrossHosts()) {
                String wstgId = finding.owaspRef().wstgId();
                if (wstgId == null) continue;
                autoCoverage.merge(wstgId, 1, Integer::sum);
            }
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() { return rows.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            WstgTestCase test = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> test.id();
                case 1 -> test.category();
                case 2 -> test.name();
                case 3 -> {
                    Integer count = autoCoverage.get(test.id());
                    yield count == null ? "" : count + " finding(s)";
                }
                case 4 -> {
                    WstgCoverageState state = wstgChecklistStore.get(test.id());
                    yield state == null ? WstgCoverageState.NOT_TESTED : state;
                }
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex != 4 || !(value instanceof WstgCoverageState state)) return;
            WstgTestCase test = rows.get(rowIndex);
            wstgChecklistStore.put(test.id(), state);
            wstgChecklistPersistenceBridge.persist(test.id(), state);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    private JPanel buildLiveTasksPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        liveTaskTableModel.refresh(liveTaskManager);
        JTable table = new JTable(liveTaskTableModel);
        table.setAutoCreateRowSorter(true);

        JButton newButton = new JButton("New");
        newButton.addActionListener(e -> {
            LiveTaskDialog dialog = new LiveTaskDialog(SwingUtilities.getWindowAncestor(root), null);
            dialog.showAndCollect(config -> {
                liveTaskManager.addOrUpdate(config);
                liveTaskTableModel.refresh(liveTaskManager);
            });
        });

        JButton editButton = new JButton("Edit");
        editButton.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            LiveTaskConfig existing = liveTaskTableModel.taskAt(table.convertRowIndexToModel(row));
            LiveTaskDialog dialog = new LiveTaskDialog(SwingUtilities.getWindowAncestor(root), existing);
            dialog.showAndCollect(config -> {
                liveTaskManager.remove(existing.name());
                liveTaskManager.addOrUpdate(config);
                liveTaskTableModel.refresh(liveTaskManager);
            });
        });

        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            LiveTaskConfig existing = liveTaskTableModel.taskAt(table.convertRowIndexToModel(row));
            liveTaskManager.remove(existing.name());
            liveTaskTableModel.refresh(liveTaskManager);
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonRow.add(newButton);
        buttonRow.add(editButton);
        buttonRow.add(deleteButton);

        panel.add(buttonRow, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private static final class LiveTaskTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Name", "Type", "Tools", "URL Scope", "Dedup", "Enabled"};
        private List<LiveTaskConfig> tasks = List.of();

        void refresh(LiveTaskManager manager) {
            tasks = manager.all();
            fireTableDataChanged();
        }

        LiveTaskConfig taskAt(int row) {
            return tasks.get(row);
        }

        @Override
        public int getRowCount() { return tasks.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            LiveTaskConfig t = tasks.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> t.name();
                case 1 -> t.taskType();
                case 2 -> t.tools().stream().map(ToolType::toolName).sorted().reduce((a, b) -> a + ", " + b).orElse("");
                case 3 -> t.urlScopeMode() + (t.urlScopeMode() == LiveTaskConfig.UrlScopeMode.CUSTOM ? " (" + t.customUrlPattern() + ")" : "");
                case 4 -> t.deduplicate();
                case 5 -> t.enabled();
                default -> "";
            };
        }
    }

    private static final class LeadsTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"URL", "Bucket", "Source", "Verified"};
        private List<Lead> leads = List.of();

        void setLeads(List<Lead> newLeads) {
            leads = newLeads;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() { return leads.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Lead lead = leads.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> lead.url();
                case 1 -> lead.bucket();
                case 2 -> lead.source();
                case 3 -> lead.verified();
                default -> "";
            };
        }
    }

    private void refreshHostList() {
        hostListModel.clear();
        for (HostNotes hostNotes : registry.allHosts()) {
            hostListModel.addElement(hostNotes.host());
        }
    }

    private void refreshForSelection() {
        if (selectedHost == null) return;
        HostNotes hostNotes = registry.hostNotesFor(selectedHost);

        List<Finding> all = new ArrayList<>(hostNotes.allFindings());
        findingsTableModel.setFindings(all);

        notesArea.setText(noteBuilder.render(hostNotes));
        notesArea.setCaretPosition(0);
    }

    private void refreshActivityLog() {
        StringBuilder sb = new StringBuilder();
        for (ActivityLog.Entry entry : activityLog.snapshot()) {
            sb.append('[').append(entry.level()).append("] ")
                    .append(entry.time()).append(' ')
                    .append(entry.module()).append(" Req #").append(entry.historyId())
                    .append(" — ").append(entry.message()).append('\n');
        }
        activityArea.setText(sb.toString());
        if (selectedHost != null) {
            refreshForSelection();
        }
    }
}
