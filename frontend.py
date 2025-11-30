# frontend.py
import sys
from typing import Dict, Optional


from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QMessageBox,
    QScrollArea,
)
from PySide6.QtCore import Qt

from backend import (
    RedTeamToolkitBackend,
    TOOL_CATEGORIES,
    Tool,
    ToolParam,
)

# =========================
#  HACKER THEME STYLESHEET
# =========================

HACKER_CSS = """
QMainWindow {
    background-color: #050608;
}

QWidget {
    background-color: #0b0c10;
    color: #66ff99;
    font-family: "Consolas", "Fira Code", monospace;
    font-size: 12pt;
}

QLabel {
    color: #66ff99;
}

QLineEdit {
    background-color: #0d1117;
    border: 2px solid #45A29E;
    border-radius: 6px;
    padding: 8px 8px;
    color: #EAF5F0;
    selection-background-color: #66ff99;
    min-height: 32px;
}

QLineEdit:focus {
    border: 2px solid #66ff99;
}

QPushButton {
    background-color: #11151c;
    border: 2px solid #45A29E;
    border-radius: 8px;
    padding: 8px 14px;
    color: #66ff99;
    font-size: 12pt;
}

QPushButton:hover {
    background-color: #18222f;
    border: 2px solid #66ff99;
}

QPushButton:pressed {
    background-color: #0b1018;
    border: 2px solid #45A29E;
}

QTreeWidget {
    background-color: #050608;
    border: 2px solid #45A29E;
    border-radius: 8px;
    color: #C5C6C7;
    font-size: 12pt;
}

QTreeWidget::item {
    padding: 5px 8px;
    margin: 2px;
}

QTreeWidget::item:selected {
    background-color: #1f2833;
    color: #66ff99;
}

QTextEdit {
    background-color: #050608;
    border: 2px solid #45A29E;
    border-radius: 8px;
    color: #EAF5F0;
    font-size: 12pt;
    padding: 8px;
}

QScrollBar:vertical, QScrollBar:horizontal {
    background: #050608;
    border: 2px solid #1f2833;
}

QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #45A29E;
}
"""


class CEHToolkitWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.backend = RedTeamToolkitBackend()
        self.selected_tool: Optional[Tool] = None
        self.selected_category: Optional[str] = None

        # name -> QLineEdit
        self.param_edits: Dict[str, QLineEdit] = {}

        self.setWindowTitle("CEH v13 Toolkit – SSH Remote")
        self.setMinimumSize(1400, 850)

        self._build_ui()

    # =========================
    #  UI CONSTRUCTION
    # =========================

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # -----------------------------------
        #  TOP: SSH CONNECTION PANEL
        # -----------------------------------
        conn_layout = QHBoxLayout()
        conn_layout.setSpacing(10)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("Host (e.g. 172.20.10.4)")
        self.host_edit.setMinimumWidth(160)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("Username")

        self.pass_edit = QLineEdit()
        self.pass_edit.setPlaceholderText("Password")
        self.pass_edit.setEchoMode(QLineEdit.Password)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.on_connect_clicked)

        conn_layout.addWidget(QLabel("Host:"))
        conn_layout.addWidget(self.host_edit)
        conn_layout.addWidget(QLabel("User:"))
        conn_layout.addWidget(self.user_edit)
        conn_layout.addWidget(QLabel("Password:"))
        conn_layout.addWidget(self.pass_edit)
        conn_layout.addWidget(self.connect_btn)

        main_layout.addLayout(conn_layout)

        # Top hint
        hint_label = QLabel("Required parameters are marked with *")
        hint_label.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(hint_label)

        # -----------------------------------
        #  MIDDLE SECTION (LEFT + RIGHT)
        # -----------------------------------
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(12)
        main_layout.addLayout(mid_layout, stretch=1)

        # -----------------------------------
        #  LEFT: TOOLS TREE
        # -----------------------------------
        self.tools_tree = QTreeWidget()
        self.tools_tree.setHeaderHidden(True)
        self.tools_tree.itemClicked.connect(self.on_tool_selected)

        for category, tools in TOOL_CATEGORIES.items():
            cat_item = QTreeWidgetItem([category])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemIsSelectable)

            for tool in tools:
                tool_item = QTreeWidgetItem([tool.name])
                tool_item.setData(0, Qt.UserRole, (category, tool.name))
                cat_item.addChild(tool_item)

            self.tools_tree.addTopLevelItem(cat_item)
            cat_item.setExpanded(True)

        mid_layout.addWidget(self.tools_tree, stretch=1)

        # -----------------------------------
        #  RIGHT PANEL (PARAMS + OUTPUT)
        # -----------------------------------
        right_layout = QVBoxLayout()
        right_layout.setSpacing(10)
        mid_layout.addLayout(right_layout, stretch=2)

        # Selected tool banner
        self.selected_tool_label = QLabel("Selected tool: (none)")
        self.selected_tool_label.setStyleSheet(
            "font-size: 17px; font-weight: bold; margin-bottom: 8px;"
        )
        right_layout.addWidget(self.selected_tool_label)

        # -----------------------------------
        #  PARAMETER FORM (SCROLLABLE + LARGE)
        # -----------------------------------
        self.params_scroll = QScrollArea()
        self.params_scroll.setWidgetResizable(True)
        self.params_scroll.setMinimumHeight(300)

        params_container = QWidget()
        self.params_layout = QVBoxLayout(params_container)
        self.params_layout.setContentsMargins(5, 5, 5, 5)
        self.params_layout.setSpacing(10)

        self.params_scroll.setWidget(params_container)
        right_layout.addWidget(self.params_scroll, stretch=0)

        # -----------------------------------
        #  BUTTONS (RUN + HELP + CLEAR)
        # -----------------------------------
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.run_btn = QPushButton("Run Tool")
        self.run_btn.clicked.connect(self.on_run_clicked)

        self.help_btn = QPushButton("Help")
        self.help_btn.clicked.connect(self.show_help)

        self.clear_btn = QPushButton("Clear Output")
        self.clear_btn.clicked.connect(lambda: self.output_edit.clear())

        btn_layout.addWidget(self.run_btn)
        btn_layout.addWidget(self.help_btn)
        btn_layout.addWidget(self.clear_btn)

        right_layout.addLayout(btn_layout)

        # -----------------------------------
        #  OUTPUT WINDOW (BIG + SCROLL + DARK)
        # -----------------------------------
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setMinimumHeight(350)
        self.output_edit.setPlaceholderText("Output from Kali will appear here...")
        right_layout.addWidget(self.output_edit, stretch=1)

    # =========================
    #  LOGGING
    # =========================

    def log(self, text: str):
        self.output_edit.append(text)

    def clear_params_form(self):
        while self.params_layout.count():
            item = self.params_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.param_edits.clear()

    def build_params_form(self, tool: Tool):
        self.clear_params_form()


        if tool.description:
            desc_label = QLabel(tool.description)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #9af7c8; margin-bottom: 8px;")
            self.params_layout.addWidget(desc_label)


        if not tool.params:
            lbl = QLabel("This tool has no parameters.")
            self.params_layout.addWidget(lbl)
            self.params_layout.addStretch(1)
            return


        for param in tool.params:
            field_box = QVBoxLayout()

            label_text = param.label + (" *" if param.required else "")
            label = QLabel(label_text)
            label.setStyleSheet("margin-bottom: 4px; font-size: 13pt;")
            field_box.addWidget(label)

            edit = QLineEdit()
            edit.setText(param.default)
            edit.setMinimumHeight(32)
            edit.setMinimumWidth(400)
            if param.placeholder:
                edit.setPlaceholderText(param.placeholder)

            field_box.addWidget(edit)
            self.param_edits[param.name] = edit

            self.params_layout.addLayout(field_box)

        self.params_layout.addStretch(1)

    # =========================
    #  EVENT HANDLERS
    # =========================

    def on_connect_clicked(self):
        if self.backend.is_connected():
            self.backend.disconnect()
            self.connect_btn.setText("Connect")
            self.log("[+] Disconnected.")
            return

        host = self.host_edit.text().strip()
        user = self.user_edit.text().strip()
        password = self.pass_edit.text().strip()

        if not host or not user or not password:
            QMessageBox.warning(self, "Missing data", "Provide host, username and password.")
            return

        try:
            self.log(f"[+] Connecting to {host} as {user}...")
            self.backend.connect(host, user, password)
            self.log("[+] Connected to Kali!")
            self.connect_btn.setText("Disconnect")
        except Exception as e:
            QMessageBox.critical(self, "SSH error", str(e))
            self.log(f"[!] SSH error: {e}")

    def on_tool_selected(self, item: QTreeWidgetItem):
        data = item.data(0, Qt.UserRole)
        if not data:
            self.selected_tool = None
            self.selected_tool_label.setText("Selected tool: (none)")
            self.clear_params_form()
            return

        category, name = data

        for tool in TOOL_CATEGORIES[category]:
            if tool.name == name:
                self.selected_tool = tool
                break

        self.selected_tool_label.setText(f"Selected tool: {name}")
        self.log(f"\n[>] Selected: {name}")
        self.build_params_form(self.selected_tool)

    def on_run_clicked(self):
        if not self.backend.is_connected():
            QMessageBox.warning(self, "Not connected", "Connect to the host first.")
            return

        if not self.selected_tool:
            QMessageBox.warning(self, "No tool", "Select a tool first.")
            return


        values = {}
        for p in self.selected_tool.params:
            value = self.param_edits[p.name].text().strip()
            if p.required and not value:
                QMessageBox.warning(self, "Missing parameter", f"Parameter '{p.label}' is required.")
                return
            values[p.name] = value

        try:
            cmd = self.selected_tool.command_template.format(**values)
        except Exception as e:
            QMessageBox.critical(self, "Format error", str(e))
            return

        self.log(f"\n[+] Running: {cmd}")

        try:
            code, out, err = self.backend.run_command(cmd)
            self.log(f"[Exit code] {code}")

            if out.strip():
                self.log("\n[OUTPUT]:")
                self.log(out)
            else:
                self.log("\n[OUTPUT]: <empty>")

            if err.strip():
                self.log("\n[ERROR]:")
                self.log(err)

        except Exception as e:
            self.log(f"[!] Execution error: {e}")

    def show_help(self):
        if not self.selected_tool:
            QMessageBox.information(self, "Help", "Select a tool first.")
            return

        text = f"=== {self.selected_tool.name} ===\n\n"

        if self.selected_tool.description:
            text += f"DESCRIPTION:\n{self.selected_tool.description}\n\n"

        text += "TEMPLATE:\n"
        text += self.selected_tool.command_template + "\n\n"

        if self.selected_tool.params:
            text += "PARAMETERS:\n"
            for p in self.selected_tool.params:
                req = " (required)" if p.required else ""
                text += f" • {p.name}: {p.label}{req}\n"
            text += "\n"

        if getattr(self.selected_tool, "help_text", ""):
            text += "FLAGS / EXTRA NOTES:\n"
            text += self.selected_tool.help_text.strip() + "\n"

        QMessageBox.information(self, f"Help – {self.selected_tool.name}", text)


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(HACKER_CSS)

    window = CEHToolkitWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
