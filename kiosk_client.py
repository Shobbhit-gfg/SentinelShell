import sys
import os
import requests
import subprocess
import keyboard
from urllib.parse import urlparse
from PyQt5.QtCore import Qt, QUrl, QTimer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                             QVBoxLayout, QInputDialog, QMessageBox, QLineEdit, QTextEdit)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage

# --- CLOUD BACKEND CONFIGURATION ---
SERVER_IP = "sentinelshell.onrender.com"
API_BASE = f"https://{SERVER_IP}/api"

CONFIG_FILE = "client_id.txt"
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
        USER_ID = f.read().strip()
else:
    USER_ID = "pc_01"

class WhitelistedWebPage(QWebEnginePage):
    def __init__(self, client_window, profile, parent=None):
        super().__init__(profile, parent)
        self.client_window = client_window

    def acceptNavigationRequest(self, url, nav_type, isMainFrame):
        url_str = url.toString()
        allowed_urls = self.client_window.config.get("allowed_urls", [])
        
        # Always allow local files (like PDFs)
        if url_str.startswith("file:///"):
            return True
        
        # 1. Check strict whitelist matches
        if any(domain in url_str for domain in allowed_urls):
            return True
            
        # 2. Allow subpages, encoding variants, helpers, or structural sub-services
        parsed_target = urlparse(url_str)
        target_domain = parsed_target.netloc.lower()
        
        for allowed in allowed_urls:
            parsed_allowed = urlparse(allowed)
            allowed_domain = parsed_allowed.netloc.lower()
            
            if target_domain and allowed_domain:
                if target_domain == allowed_domain or target_domain.endswith("." + allowed_domain) or allowed_domain.endswith("." + target_domain):
                    return True
                if "base64" in target_domain and "base64" in allowed_domain:
                    return True
                if "codebeautify" in target_domain or "browserling" in target_domain:
                    return True
                # Allow standard helper domains (Stripe scripts, Google Tag/Analytics pixels, Cloudflare, etc.)
                if any(ext in target_domain for ext in ["stripe.com", "doubleclick.net", "googletagmanager.com", "cloudflare.com"]):
                    return True

        # Block and log unauthorized navigation if it doesn't match any rule
        print(f"Blocked navigation to: {url_str}")
        try:
            requests.post(f"{API_BASE}/logs", json={
                "user_id": USER_ID,
                "event_type": "URL_BLOCKED",
                "details": url_str
            }, timeout=3)
        except Exception:
            pass
        return False

class SandboxedTerminal(QWidget):
    def __init__(self, client_window):
        super().__init__()
        self.client_window = client_window
        layout = QVBoxLayout()
        
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("background-color: black; color: green; font-family: monospace;")
        
        self.input_line = QLineEdit()
        self.input_line.setStyleSheet("background-color: black; color: white; font-family: monospace;")
        self.input_line.returnPressed.connect(self.execute_command)
        
        layout.addWidget(self.output_area)
        layout.addWidget(self.input_line)
        self.setLayout(layout)

    def execute_command(self):
        cmd = self.input_line.text().strip()
        self.input_line.clear()
        self.output_area.append(f"> {cmd}")
        
        allowed_commands = self.client_window.config.get("allowed_commands", [])
        
        if cmd not in allowed_commands:
            self.output_area.append("ERROR: Command not whitelisted by Administrator.\n")
            try:
                requests.post(f"{API_BASE}/logs", json={"user_id": USER_ID, "event_type": "CMD_BLOCKED", "details": cmd}, timeout=3)
            except Exception:
                pass
            return
            
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            self.output_area.append(result.stdout)
            if result.stderr:
                self.output_area.append(result.stderr)
        except Exception as e:
            self.output_area.append(f"Execution failed: {str(e)}\n")

class KioskWindow(QMainWindow):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.init_ui()
        self.trap_system_keys()
        
        self.sync_timer = QTimer(self)
        self.sync_timer.timeout.connect(self.fetch_latest_config)
        self.sync_timer.start(10000)

    def init_ui(self):
        self.setWindowTitle("SentinelShell Kiosk")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.X11BypassWindowManagerHint)
        self.showFullScreen()
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.build_tabs_from_config()

    def build_tabs_from_config(self):
        self.tabs.clear()
        tab_list = self.config.get("tabs", [])
        allowed_urls = self.config.get("allowed_urls", [])

        for tab in tab_list:
            if isinstance(tab, dict):
                name = tab.get("name", "Tab")
                t_type = tab.get("type", "url")
                val = tab.get("value", "")

                if t_type == "terminal":
                    self.add_terminal_tab(name)
                elif t_type in ["pdf", "image"]:
                    if os.path.exists(val):
                        file_url = QUrl.fromLocalFile(os.path.abspath(val)).toString()
                    else:
                        file_url = val
                    self.add_web_tab(file_url, name)
                else:
                    self.add_web_tab(val, name)
            else:
                tab_name = str(tab)
                if tab_name.lower() == "terminal" or "config" in tab_name.lower():
                    self.add_terminal_tab(tab_name)
                else:
                    target_url = allowed_urls[0] if allowed_urls else "https://python.org"
                    for url in allowed_urls:
                        keyword = tab_name.lower().replace(" ", "").replace("docs", "").replace("portal", "")
                        if keyword and keyword in url.lower():
                            target_url = url
                            break
                    self.add_web_tab(target_url, tab_name)

    def add_web_tab(self, url, title):
        browser = QWebEngineView()
        page = WhitelistedWebPage(self, browser.page().profile(), browser)
        browser.setPage(page)
        browser.setUrl(QUrl(url))
        self.tabs.addTab(browser, title)

    def add_terminal_tab(self, title):
        terminal = SandboxedTerminal(self)
        self.tabs.addTab(terminal, title)

    def fetch_latest_config(self):
        try:
            response = requests.get(f"{API_BASE}/config/{USER_ID}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "banned":
                    QMessageBox.critical(self, "Access Revoked", "This device has been banned by the administrator.")
                    keyboard.unhook_all()
                    sys.exit(0)
                
                if data.get("tabs") != self.config.get("tabs"):
                    self.config = data
                    self.build_tabs_from_config()
                else:
                    self.config = data
        except Exception:
            pass

    def trap_system_keys(self):
        try:
            keyboard.block_key('windows')
            keyboard.block_key('alt')
        except Exception as e:
            print("System key trapping requires root/admin privileges.")

    def keyPressEvent(self, event):
        if event.modifiers() == (Qt.ControlModifier | Qt.ShiftModifier) and event.key() == Qt.Key_X:
            self.trigger_exit_protocol()
        else:
            super().keyPressEvent(event)

    def trigger_exit_protocol(self):
        password, ok = QInputDialog.getText(self, 'Admin Override', 'Enter Administrator Password:', QLineEdit.Password)
        if ok and password == self.config.get("admin_password", ""):
            keyboard.unhook_all()
            QApplication.quit()
        else:
            try:
                requests.post(f"{API_BASE}/logs", json={"user_id": USER_ID, "event_type": "FAILED_EXIT", "details": "Invalid admin password attempt"}, timeout=3)
            except Exception:
                pass
            QMessageBox.critical(self, 'Access Denied', 'Security violation logged.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    target_url = f"{API_BASE}/config/{USER_ID}"
    print(f"Connecting to cloud server at: {target_url}")
    
    try:
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        config = response.json()
        if config.get("status") == "banned":
            print("Client device is currently banned. Halting boot.")
            sys.exit(1)
    except Exception as e:
        print(f"\n[BOOT ERROR] Unable to connect to cloud server.")
        print(f"Details: {e}")
        print("Please check your internet connection or cloud service status.\n")
        sys.exit(1)
        
    kiosk = KioskWindow(config)
    sys.exit(app.exec_())