package com.crushed.ui;

import com.crushed.model.Severity;
import com.crushed.model.Status;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/** Colors the Severity/Status columns of the findings table, matching Burp Pro's issue-severity palette. */
public final class SeverityCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                    boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value instanceof Severity severity) {
            setForeground(Color.WHITE);
            setBackground(isSelected ? SeverityPalette.forSeverity(severity).darker() : SeverityPalette.forSeverity(severity));
            setFont(getFont().deriveFont(Font.BOLD));
        } else if (value instanceof Status status) {
            setBackground(table.getBackground());
            setForeground(SeverityPalette.forStatus(status));
            setFont(getFont().deriveFont(status == Status.CONFIRMED ? Font.BOLD : Font.PLAIN));
        }
        return c;
    }
}
