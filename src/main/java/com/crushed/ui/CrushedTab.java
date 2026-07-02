package com.crushed.ui;

import com.crushed.core.EndpointRegistry;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.TriageState;
import com.crushed.notes.MarkdownNoteBuilder;
import com.crushed.notes.NoteExporter;
import com.crushed.recon.Lead;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Main Swing tab: host list + findings table + notes viewer + Activity/Errors log + Settings. */
public final class CrushedTab {

    private final EndpointRegistry registry;
    private final ActivityLog activityLog;
    private final SettingsPanel settingsPanel;
    private final FindingActionHandler actionHandler;
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
    private volatile String selectedHost;

    public CrushedTab(EndpointRegistry registry, ActivityLog activityLog, SettingsPanel settingsPanel,
                       FindingActionHandler actionHandler) {
        this.registry = registry;
        this.activityLog = activityLog;
        this.settingsPanel = settingsPanel;
        this.actionHandler = actionHandler;
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

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(topRow);
        north.add(seedRow);
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
