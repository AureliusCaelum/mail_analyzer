"""
Konfigurationsoberfläche für kontextbasierte Regeln
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QTreeWidget, QTreeWidgetItem, QDialog, QFormLayout,
    QSpinBox, QMessageBox, QScrollArea
)
from PyQt6.QtCore import Qt
import json
import os
from typing import Dict, List

class RuleConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Neue Regel erstellen")
        self.setModal(True)
        self.initUI()

    def initUI(self):
        layout = QFormLayout(self)

        # Regel-Typ
        self.rule_type = QComboBox()
        self.rule_type.addItems([
            "Abteilungsregel", "Rollenregel", "Kontaktregel",
            "Bedrohungsmuster", "Zeitbasierte Regel"
        ])
        layout.addRow("Regeltyp:", self.rule_type)

        # Name
        self.rule_name = QLineEdit()
        layout.addRow("Name:", self.rule_name)

        # Ziel
        self.target = QComboBox()
        self.rule_type.currentTextChanged.connect(self._update_target_options)
        layout.addRow("Ziel:", self.target)

        # Bedingungen
        self.condition = QLineEdit()
        layout.addRow("Bedingung:", self.condition)

        # Gewichtung
        self.weight = QSpinBox()
        self.weight.setRange(1, 10)
        self.weight.setValue(5)
        layout.addRow("Gewichtung:", self.weight)

        # Buttons
        buttons = QHBoxLayout()
        save_btn = QPushButton("Speichern")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Abbrechen")
        cancel_btn.clicked.connect(self.reject)

        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)
        layout.addRow(buttons)

    def _update_target_options(self):
        """Aktualisiert die Zieloptionen basierend auf dem Regeltyp"""
        self.target.clear()
        rule_type = self.rule_type.currentText()

        if rule_type == "Abteilungsregel":
            self.target.addItems(["IT", "Finanzen", "HR", "Marketing", "Vertrieb"])
        elif rule_type == "Rollenregel":
            self.target.addItems(["Admin", "Manager", "Mitarbeiter", "Praktikant"])
        elif rule_type == "Kontaktregel":
            self.target.addItems(["Intern", "Extern", "Partner", "Kunde"])
        elif rule_type == "Bedrohungsmuster":
            self.target.addItems(["Phishing", "Malware", "Spam", "Social Engineering"])
        elif rule_type == "Zeitbasierte Regel":
            self.target.addItems(["Arbeitszeit", "Außerhalb", "Wochenende"])

    def get_rule_data(self) -> Dict:
        """Gibt die Regeldaten zurück"""
        return {
            "type": self.rule_type.currentText(),
            "name": self.rule_name.text(),
            "target": self.target.currentText(),
            "condition": self.condition.text(),
            "weight": self.weight.value()
        }

class ContextRuleConfig(QWidget):
    def __init__(self, context_analyzer, parent=None):
        super().__init__(parent)
        self.context_analyzer = context_analyzer
        self.rules_file = "config/context_rules.json"
        self.rules = self._load_rules()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QHBoxLayout()
        add_btn = QPushButton("Neue Regel")
        add_btn.clicked.connect(self.add_rule)
        edit_btn = QPushButton("Bearbeiten")
        edit_btn.clicked.connect(self.edit_rule)
        delete_btn = QPushButton("Löschen")
        delete_btn.clicked.connect(self.delete_rule)

        toolbar.addWidget(add_btn)
        toolbar.addWidget(edit_btn)
        toolbar.addWidget(delete_btn)
        toolbar.addStretch()

        layout.addLayout(toolbar)

        # Regel-Baum
        self.rule_tree = QTreeWidget()
        self.rule_tree.setHeaderLabels([
            "Name", "Typ", "Ziel", "Gewichtung", "Status"
        ])
        self.rule_tree.setColumnWidth(0, 200)

        layout.addWidget(self.rule_tree)

        # Lade Regeln
        self._populate_rule_tree()

        # Kontext-Konfiguration
        context_group = QWidget()
        context_layout = QFormLayout(context_group)

        # Abteilungen
        self.dept_edit = QLineEdit()
        self.dept_edit.setText(", ".join(self._get_departments()))
        context_layout.addRow("Abteilungen:", self.dept_edit)

        # Rollen
        self.roles_edit = QLineEdit()
        self.roles_edit.setText(", ".join(self._get_roles()))
        context_layout.addRow("Rollen:", self.roles_edit)

        # Speichern-Button
        save_context_btn = QPushButton("Kontext speichern")
        save_context_btn.clicked.connect(self.save_context)
        context_layout.addRow(save_context_btn)

        layout.addWidget(context_group)

    def add_rule(self):
        """Fügt eine neue Regel hinzu"""
        dialog = RuleConfigDialog(self)
        if dialog.exec():
            rule_data = dialog.get_rule_data()
            rule_id = f"rule_{len(self.rules) + 1}"
            self.rules[rule_id] = rule_data
            self._save_rules()
            self._populate_rule_tree()

    def edit_rule(self):
        """Bearbeitet eine ausgewählte Regel"""
        current = self.rule_tree.currentItem()
        if not current:
            return

        rule_id = current.data(0, Qt.ItemDataRole.UserRole)
        rule_data = self.rules.get(rule_id)
        if not rule_data:
            return

        dialog = RuleConfigDialog(self)
        dialog.rule_type.setCurrentText(rule_data["type"])
        dialog.rule_name.setText(rule_data["name"])
        dialog.target.setCurrentText(rule_data["target"])
        dialog.condition.setText(rule_data["condition"])
        dialog.weight.setValue(rule_data["weight"])

        if dialog.exec():
            self.rules[rule_id] = dialog.get_rule_data()
            self._save_rules()
            self._populate_rule_tree()

    def delete_rule(self):
        """Löscht eine ausgewählte Regel"""
        current = self.rule_tree.currentItem()
        if not current:
            return

        rule_id = current.data(0, Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self,
            "Regel löschen",
            "Möchten Sie diese Regel wirklich löschen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            del self.rules[rule_id]
            self._save_rules()
            self._populate_rule_tree()

    def save_context(self):
        """Speichert die Kontexteinstellungen"""
        departments = [d.strip() for d in self.dept_edit.text().split(",") if d.strip()]
        roles = [r.strip() for r in self.roles_edit.text().split(",") if r.strip()]

        context_data = {
            "departments": departments,
            "roles": roles
        }

        self.context_analyzer.update_organization_context(context_data)
        QMessageBox.information(
            self,
            "Erfolg",
            "Kontext wurde erfolgreich aktualisiert"
        )

    def _populate_rule_tree(self):
        """Füllt den Regel-Baum mit den aktuellen Regeln"""
        self.rule_tree.clear()

        # Gruppiere Regeln nach Typ
        rule_groups = {}
        for rule_id, rule in self.rules.items():
            rule_type = rule["type"]
            if rule_type not in rule_groups:
                rule_groups[rule_type] = []
            rule_groups[rule_type].append((rule_id, rule))

        # Fülle Baum
        for rule_type, rules in rule_groups.items():
            type_item = QTreeWidgetItem([rule_type])
            self.rule_tree.addTopLevelItem(type_item)

            for rule_id, rule in rules:
                rule_item = QTreeWidgetItem([
                    rule["name"],
                    rule["type"],
                    rule["target"],
                    str(rule["weight"]),
                    "Aktiv"
                ])
                rule_item.setData(0, Qt.ItemDataRole.UserRole, rule_id)
                type_item.addChild(rule_item)

        self.rule_tree.expandAll()

    def _load_rules(self) -> Dict:
        """Lädt die gespeicherten Regeln"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Fehler beim Laden der Regeln: {str(e)}")
            return {}

    def _save_rules(self) -> None:
        """Speichert die Regeln"""
        try:
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            with open(self.rules_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
        except Exception as e:
            print(f"Fehler beim Speichern der Regeln: {str(e)}")

    def _get_departments(self) -> List[str]:
        """Holt die konfigurierten Abteilungen"""
        context = self.context_analyzer.org_context
        return context.get("departments", ["IT", "Finanzen", "HR", "Marketing", "Vertrieb"])

    def _get_roles(self) -> List[str]:
        """Holt die konfigurierten Rollen"""
        context = self.context_analyzer.org_context
        return context.get("roles", ["Admin", "Manager", "Mitarbeiter", "Praktikant"])
