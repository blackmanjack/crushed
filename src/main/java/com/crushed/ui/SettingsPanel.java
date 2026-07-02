package com.crushed.ui;

import com.crushed.identitydiff.Identity;
import com.crushed.identitydiff.IdentityRegistry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;

/**
 * Toggles for every Iterasi-2 module. All default OFF/disabled per the plan; Active mode
 * gates active detectors + identity diff + OAST from ever sending traffic until explicitly
 * enabled by the user.
 */
public final class SettingsPanel {

    private final JCheckBox activeModeToggle = new JCheckBox("Active mode (sends probe traffic to in-scope hosts)");
    private final JCheckBox identityDiffToggle = new JCheckBox("Identity Diff Engine (Autorize-style replay)");
    private final JCheckBox crawlingToggle = new JCheckBox("Crawling (DIY crawler + Site Map response backfill)");
    private final JTextField crawlMaxRequestsField = new JTextField("100", 5);
    private final JTextField crawlMaxDepthField = new JTextField("3", 5);
    private final JTextField crawlDelayMsField = new JTextField("300", 5);
    private final JCheckBox oastToggle = new JCheckBox("OAST (Interactsh) confirmation");
    private final JCheckBox aiToggle = new JCheckBox("AI analysis (Claude) — sends redacted summaries");
    private final JCheckBox yandexToggle = new JCheckBox("Yandex dorking recon (leads only, no auto-fetch)");
    private final JCheckBox sessionColorToggle = new JCheckBox("Color-code HTTP history by session/account (overwrites existing highlight)");
    private final JTextField apiKeyField = new JTextField(30);
    private final JTextField oastServerField = new JTextField("oast.pro", 20);

    private final IdentityRegistry identityRegistry;
    private final IdentityTableModel identityTableModel = new IdentityTableModel();
    private final JTextField identityLabelField = new JTextField(12);
    private final JTextField identityCookieField = new JTextField(20);
    private final JTextField identityBearerField = new JTextField(20);

    private final JPanel root;

    public SettingsPanel(IdentityRegistry identityRegistry) {
        this.identityRegistry = identityRegistry;

        // All OFF by default.
        activeModeToggle.setSelected(false);
        identityDiffToggle.setSelected(false);
        oastToggle.setSelected(false);
        aiToggle.setSelected(false);
        yandexToggle.setSelected(false);
        // Purely cosmetic and passive (no traffic sent) — safe to default ON.
        sessionColorToggle.setSelected(true);

        crawlingToggle.setSelected(false);

        // Sub-modules that send traffic require Active mode to be on first.
        identityDiffToggle.setEnabled(false);
        oastToggle.setEnabled(false);
        crawlingToggle.setEnabled(false);
        activeModeToggle.addActionListener(e -> {
            boolean on = activeModeToggle.isSelected();
            identityDiffToggle.setEnabled(on);
            oastToggle.setEnabled(on);
            crawlingToggle.setEnabled(on);
            if (!on) {
                identityDiffToggle.setSelected(false);
                oastToggle.setSelected(false);
                crawlingToggle.setSelected(false);
            }
        });

        root = build();
    }

    private JPanel build() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        panel.add(activeModeToggle);
        panel.add(indent(identityDiffToggle));
        panel.add(indent(buildIdentityManagementPanel()));
        panel.add(indent(oastToggle));
        panel.add(labeledRow("Interactsh server:", oastServerField));
        panel.add(Box.createVerticalStrut(10));
        panel.add(indent(crawlingToggle));
        panel.add(labeledRow("Max requests / depth / delay ms:", crawlConfigRow()));
        panel.add(Box.createVerticalStrut(10));
        panel.add(aiToggle);
        panel.add(labeledRow("Anthropic API key:", apiKeyField));
        panel.add(Box.createVerticalStrut(10));
        panel.add(yandexToggle);
        panel.add(Box.createVerticalStrut(10));
        panel.add(sessionColorToggle);

        return panel;
    }

    private JPanel buildIdentityManagementPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Identities for replay-based authz testing"));

        JTable table = new JTable(identityTableModel);
        table.setPreferredScrollableViewportSize(new Dimension(400, 80));
        JScrollPane scrollPane = new JScrollPane(table);

        JPanel addRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addRow.add(new JLabel("Label:"));
        addRow.add(identityLabelField);
        addRow.add(new JLabel("Cookie:"));
        addRow.add(identityCookieField);
        addRow.add(new JLabel("Authorization:"));
        addRow.add(identityBearerField);

        JButton addButton = new JButton("Add / Update");
        addButton.addActionListener(e -> {
            String label = identityLabelField.getText().trim();
            if (label.isEmpty()) return;
            String cookie = identityCookieField.getText().trim();
            String bearer = identityBearerField.getText().trim();
            identityRegistry.add(new Identity(label, bearer.isEmpty() ? null : bearer, cookie.isEmpty() ? null : cookie));
            identityTableModel.refresh(identityRegistry);
            identityLabelField.setText("");
            identityCookieField.setText("");
            identityBearerField.setText("");
        });

        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            identityRegistry.remove(identityTableModel.labelAt(row));
            identityTableModel.refresh(identityRegistry);
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonRow.add(addButton);
        buttonRow.add(removeButton);

        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(addRow, BorderLayout.NORTH);
        southPanel.add(buttonRow, BorderLayout.SOUTH);

        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(southPanel, BorderLayout.SOUTH);
        return panel;
    }

    private static final class IdentityTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Label", "Has Cookie", "Has Authorization"};
        private java.util.List<Identity> identities = java.util.List.of();

        void refresh(IdentityRegistry registry) {
            identities = registry.all();
            fireTableDataChanged();
        }

        String labelAt(int row) {
            return identities.get(row).label();
        }

        @Override
        public int getRowCount() { return identities.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Identity identity = identities.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> identity.label();
                case 1 -> identity.hasCookie();
                case 2 -> identity.hasBearer();
                default -> "";
            };
        }
    }

    private JPanel crawlConfigRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        p.add(crawlMaxRequestsField);
        p.add(crawlMaxDepthField);
        p.add(crawlDelayMsField);
        return p;
    }

    private JPanel indent(JComponent c) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(Box.createHorizontalStrut(20));
        p.add(c);
        return p;
    }

    private JPanel labeledRow(String label, JComponent field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(Box.createHorizontalStrut(20));
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    public Component component() {
        return root;
    }

    public boolean isActiveModeEnabled() { return activeModeToggle.isSelected(); }
    public boolean isIdentityDiffEnabled() { return identityDiffToggle.isSelected(); }
    public boolean isOastEnabled() { return oastToggle.isSelected(); }
    public boolean isAiEnabled() { return aiToggle.isSelected(); }
    public boolean isYandexEnabled() { return yandexToggle.isSelected(); }
    public boolean isSessionColorCodingEnabled() { return sessionColorToggle.isSelected(); }
    public boolean isCrawlingEnabled() { return crawlingToggle.isSelected(); }
    public String apiKey() { return apiKeyField.getText(); }
    public String oastServer() { return oastServerField.getText().isBlank() ? "oast.pro" : oastServerField.getText().trim(); }

    public int crawlMaxRequests() { return parseIntOrDefault(crawlMaxRequestsField.getText(), 100); }
    public int crawlMaxDepth() { return parseIntOrDefault(crawlMaxDepthField.getText(), 3); }
    public int crawlDelayMs() { return parseIntOrDefault(crawlDelayMsField.getText(), 300); }

    private int parseIntOrDefault(String text, int defaultValue) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }
}
