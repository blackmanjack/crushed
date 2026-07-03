package com.crushed.ui;

import burp.api.montoya.core.ToolType;
import com.crushed.model.LiveTaskConfig;

import javax.swing.*;
import java.awt.*;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * "New Live Task" wizard, mirroring Burp Pro's own dialog: a left-nav step list ("Scan details",
 * "Resource pool") and a right-side form (Task type, Tools scope, URL scope, Deduplication).
 * "Scan configuration" is folded into "Scan details" for this first version — crushed doesn't
 * have a second configuration layer beyond what's already on this one page.
 */
public final class LiveTaskDialog extends JDialog {

    private final JRadioButton passiveOnly = new JRadioButton("Live passive analysis");
    private final JRadioButton passivePlusActive = new JRadioButton("Live passive analysis + active confirmation");

    private final JCheckBox proxyTool = new JCheckBox("Proxy");
    private final JCheckBox repeaterTool = new JCheckBox("Repeater");
    private final JCheckBox intruderTool = new JCheckBox("Intruder");

    private final JRadioButton everythingScope = new JRadioButton("Everything");
    private final JRadioButton suiteScope = new JRadioButton("Suite scope");
    private final JRadioButton customScope = new JRadioButton("Custom scope");
    private final JTextField customScopeField = new JTextField(24);

    private final JCheckBox deduplicateBox = new JCheckBox("Ignore duplicate items based on URL and parameter names");
    private final JTextField nameField = new JTextField(24);

    private boolean saved = false;

    public LiveTaskDialog(Window owner, LiveTaskConfig existing) {
        super(owner, "New Live Task", ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout());

        ButtonGroup taskTypeGroup = new ButtonGroup();
        taskTypeGroup.add(passiveOnly);
        taskTypeGroup.add(passivePlusActive);

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(everythingScope);
        scopeGroup.add(suiteScope);
        scopeGroup.add(customScope);
        customScopeField.setEnabled(false);
        customScope.addActionListener(e -> customScopeField.setEnabled(true));
        everythingScope.addActionListener(e -> customScopeField.setEnabled(false));
        suiteScope.addActionListener(e -> customScopeField.setEnabled(false));

        DefaultListModel<String> stepsModel = new DefaultListModel<>();
        stepsModel.addElement("Scan details");
        stepsModel.addElement("Resource pool");
        JList<String> steps = new JList<>(stepsModel);
        steps.setSelectedIndex(0);
        steps.setPreferredSize(new Dimension(140, 0));

        JPanel scanDetailsPage = buildScanDetailsPage();
        JPanel resourcePoolPage = buildResourcePoolStubPage();

        CardLayout cards = new CardLayout();
        JPanel cardPanel = new JPanel(cards);
        cardPanel.add(scanDetailsPage, "Scan details");
        cardPanel.add(resourcePoolPage, "Resource pool");
        steps.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) cards.show(cardPanel, steps.getSelectedValue());
        });

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            saved = true;
            dispose();
        });
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(cancelButton);
        buttonRow.add(saveButton);

        add(steps, BorderLayout.WEST);
        add(cardPanel, BorderLayout.CENTER);
        add(buttonRow, BorderLayout.SOUTH);

        populateFrom(existing);
        setSize(560, 420);
        setLocationRelativeTo(owner);
    }

    private JPanel buildScanDetailsPage() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        panel.add(labeledRow("Name:", nameField));
        panel.add(Box.createVerticalStrut(10));

        panel.add(new JLabel("Task type"));
        panel.add(passiveOnly);
        panel.add(passivePlusActive);
        panel.add(Box.createVerticalStrut(10));

        panel.add(new JLabel("Tools scope"));
        JPanel toolsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolsRow.add(proxyTool);
        toolsRow.add(repeaterTool);
        toolsRow.add(intruderTool);
        panel.add(toolsRow);
        panel.add(Box.createVerticalStrut(10));

        panel.add(new JLabel("URL scope"));
        panel.add(everythingScope);
        panel.add(suiteScope);
        JPanel customRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        customRow.add(customScope);
        customRow.add(customScopeField);
        panel.add(customRow);
        panel.add(Box.createVerticalStrut(10));

        panel.add(new JLabel("Deduplication"));
        panel.add(deduplicateBox);

        return panel;
    }

    private JPanel buildResourcePoolStubPage() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(new JLabel("<html>Not applicable — crushed processes each request synchronously "
                + "as it arrives; there is no thread pool to tune.</html>"), BorderLayout.NORTH);
        return panel;
    }

    private JPanel labeledRow(String label, JComponent field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    private void populateFrom(LiveTaskConfig existing) {
        if (existing == null) {
            passiveOnly.setSelected(true);
            proxyTool.setSelected(true);
            suiteScope.setSelected(true);
            return;
        }
        nameField.setText(existing.name());
        if (existing.taskType() == LiveTaskConfig.TaskType.PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM) {
            passivePlusActive.setSelected(true);
        } else {
            passiveOnly.setSelected(true);
        }
        proxyTool.setSelected(existing.tools().contains(ToolType.PROXY));
        repeaterTool.setSelected(existing.tools().contains(ToolType.REPEATER));
        intruderTool.setSelected(existing.tools().contains(ToolType.INTRUDER));
        switch (existing.urlScopeMode()) {
            case EVERYTHING -> everythingScope.setSelected(true);
            case SUITE_SCOPE -> suiteScope.setSelected(true);
            case CUSTOM -> {
                customScope.setSelected(true);
                customScopeField.setEnabled(true);
                customScopeField.setText(existing.customUrlPattern() == null ? "" : existing.customUrlPattern());
            }
        }
        deduplicateBox.setSelected(existing.deduplicate());
    }

    /** Shows the dialog and, if saved, invokes the callback with the resulting config. */
    public void showAndCollect(Consumer<LiveTaskConfig> onSave) {
        setVisible(true);
        if (!saved) return;

        String name = nameField.getText().trim();
        if (name.isEmpty()) name = "Live Task " + System.currentTimeMillis();

        LiveTaskConfig.TaskType taskType = passivePlusActive.isSelected()
                ? LiveTaskConfig.TaskType.PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM
                : LiveTaskConfig.TaskType.PASSIVE_ANALYSIS;

        Set<ToolType> tools = EnumSet.noneOf(ToolType.class);
        if (proxyTool.isSelected()) tools.add(ToolType.PROXY);
        if (repeaterTool.isSelected()) tools.add(ToolType.REPEATER);
        if (intruderTool.isSelected()) tools.add(ToolType.INTRUDER);
        if (tools.isEmpty()) tools.add(ToolType.PROXY);

        LiveTaskConfig.UrlScopeMode scopeMode = customScope.isSelected()
                ? LiveTaskConfig.UrlScopeMode.CUSTOM
                : (everythingScope.isSelected() ? LiveTaskConfig.UrlScopeMode.EVERYTHING : LiveTaskConfig.UrlScopeMode.SUITE_SCOPE);

        onSave.accept(new LiveTaskConfig(name, taskType, tools, scopeMode,
                customScopeField.getText().trim(), deduplicateBox.isSelected(), true));
    }
}
