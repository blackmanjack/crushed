package com.crushed.ui;

import com.crushed.model.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class FindingsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"Status", "Severity", "Confidence", "Issue Type", "Endpoint", "Triage"};

    private final List<Finding> findings = new ArrayList<>();

    public void setFindings(List<Finding> newFindings) {
        findings.clear();
        findings.addAll(newFindings);
        fireTableDataChanged();
    }

    public Finding findingAt(int row) {
        return findings.get(row);
    }

    @Override
    public int getRowCount() {
        return findings.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Finding f = findings.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> f.status();
            case 1 -> f.severity();
            case 2 -> f.confidence();
            case 3 -> f.issueType().displayName();
            case 4 -> f.endpointKey();
            case 5 -> f.triageState();
            default -> "";
        };
    }
}
