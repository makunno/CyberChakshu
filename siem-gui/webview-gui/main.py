"""FreeKhana SIEM Desktop - PySide6 GUI with Embedded WebView and Terminal"""

import sys
import os
import requests
import threading
import time
import io
import subprocess
from pathlib import Path
from datetime import datetime

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QGroupBox, QStatusBar,
    QMessageBox, QProgressBar, QFrame, QSplitter, QTabWidget, QPlainTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QObject
from PySide6.QtGui import QFont, QPalette, QColor, QIcon, QTextCursor

# WebView imports - using Qt WebEngine instead of pywebview for better integration
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEngineSettings
WEBVIEW_AVAILABLE = True

# Flask API imports (for local backend) - lazy loading
FLASK_AVAILABLE = True


class FlaskOutputCapture(QObject):
    """Capture Flask server output"""
    output = Signal(str)

    def __init__(self):
        super().__init__()
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.buffer = io.StringIO()
        self.running = False

    def start_capture(self):
        """Start capturing stdout/stderr"""
        self.running = True
        self.buffer = io.StringIO()
        sys.stdout = self
        sys.stderr = self

    def stop_capture(self):
        """Stop capturing and restore original streams"""
        if self.running:
            self.running = False
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr

    def write(self, text):
        """Write to buffer and emit signal"""
        if self.running:
            self.buffer.write(text)
            self.output.emit(text)

    def flush(self):
        """Flush the buffer"""
        if self.running:
            self.buffer.flush()

    def get_output(self):
        """Get all captured output"""
        return self.buffer.getvalue()


class FlaskServer(QThread):
    """Thread to run Flask server"""
    server_started = Signal()
    server_error = Signal(str)
    server_output = Signal(str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._shutdown = False
        self.server = None
        self.capture = FlaskOutputCapture()
        self.capture.output.connect(self.on_server_output)

    def run(self):
        try:
            from api.app import app as flask_app
            self.running = True

            # Capture Flask output
            self.capture.start_capture()

            # Run Flask with proper shutdown handling
            from werkzeug.serving import make_server
            self.server = make_server('127.0.0.1', 5000, flask_app, threaded=True)
            self.server_started.emit()

            # Serve requests until shutdown
            self.server.serve_forever()

        except ImportError:
            if not self._shutdown:
                self.server_error.emit("Flask backend not available")
        except Exception as e:
            if not self._shutdown:
                self.server_error.emit(str(e))
        finally:
            self.running = False
            self.capture.stop_capture()
            if self.server:
                try:
                    self.server.shutdown()
                except:
                    pass

    def stop(self):
        """Stop the Flask server"""
        self._shutdown = True
        self.running = False

        if self.server:
            try:
                self.server.shutdown()
                import time
                time.sleep(0.5)
            except:
                pass

        if self.isRunning():
            self.terminate()
            if not self.wait(3000):
                print("Warning: Flask thread did not terminate cleanly")

    def on_server_output(self, text):
        """Emit server output to UI"""
        self.server_output.emit(text)


class BackendChecker(QThread):
    """Thread to check backend availability"""
    result_ready = Signal(str, bool)

    def __init__(self, backend_type, url):
        super().__init__()
        self.backend_type = backend_type
        self.url = url
        self._stopping = False

    def run(self):
        try:
            if self.backend_type == 'localhost':
                response = requests.get(f'{self.url}/parsers', timeout=3)
                available = response.status_code == 200
            else:
                response = requests.get(f'{self.url}/parsers', timeout=5)
                available = response.status_code == 200
        except Exception as e:
            available = False

        self.result_ready.emit(self.backend_type, available)

    def stop(self):
        self._stopping = True


class FreeKhanaMainWindow(QMainWindow):
    """Main application window with PySide6 controls, embedded WebView and Terminal"""

    def __init__(self):
        super().__init__()
        self.current_backend = None
        self.webview_widget = None
        self.flask_thread = None
        self.flask_server_running = False
        self.backend_checkers = []
        self.terminal_output = ""
        self.current_tab = "webview"
        self.initial_load = True  # Track if this is the initial load  # 'webview' or 'terminal'

        self.init_ui()
        self.check_backends()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FreeKhana SIEM Desktop")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        # Backend selection panel (top)
        self.create_backend_panel()
        main_layout.addWidget(self.backend_panel)

        # Tab widget for WebView and Terminal
        self.create_tab_container()
        main_layout.addWidget(self.tab_widget, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Initializing...")

        # Apply modern styling
        self.apply_modern_style()

    def create_backend_panel(self):
        """Create the backend selection panel"""
        self.backend_panel = QGroupBox("Backend Configuration")
        self.backend_panel.setMaximumHeight(100)

        layout = QHBoxLayout(self.backend_panel)

        # Backend selector
        layout.addWidget(QLabel("Backend:"))
        self.backend_combo = QComboBox()
        self.backend_combo.addItem("Offline (Local)", "localhost")
        self.backend_combo.addItem("Online (Cloud)", "online")
        self.backend_combo.currentTextChanged.connect(self.on_backend_changed)
        layout.addWidget(self.backend_combo)

        # Status indicators
        self.local_status = QLabel("Offline: Checking...")
        self.online_status = QLabel("Online: Checking...")
        layout.addWidget(self.local_status)
        layout.addWidget(self.online_status)

        # Refresh button
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.check_backends)
        layout.addWidget(refresh_btn)

        # Start/Stop Local button
        self.start_local_btn = QPushButton("Start Local Backend")
        self.start_local_btn.clicked.connect(self.start_local_backend)
        self.start_local_btn.setEnabled(False)
        layout.addWidget(self.start_local_btn)

        # Stop Local button
        self.stop_local_btn = QPushButton("Stop Local Backend")
        self.stop_local_btn.clicked.connect(self.stop_local_backend)
        self.stop_local_btn.setEnabled(False)
        self.stop_local_btn.setVisible(False)
        layout.addWidget(self.stop_local_btn)

        # Restart Local Server button (only active when server is running)
        self.restart_local_btn = QPushButton("Restart Local Server")
        self.restart_local_btn.clicked.connect(self.restart_local_backend)
        self.restart_local_btn.setEnabled(False)
        layout.addWidget(self.restart_local_btn)

        layout.addStretch()

    def create_tab_container(self):
        """Create tab widget for WebView and Terminal"""
        self.tab_widget = QTabWidget()

        # WebView tab
        self.webview_tab = QWidget()
        webview_layout = QVBoxLayout(self.webview_tab)
        self.create_webview_container()
        webview_layout.addWidget(self.webview_container)
        self.tab_widget.addTab(self.webview_tab, "WebView")

        # Terminal tab
        self.terminal_tab = QWidget()
        terminal_layout = QVBoxLayout(self.terminal_tab)
        self.create_terminal_container()
        terminal_layout.addWidget(self.terminal_container)
        self.tab_widget.addTab(self.terminal_tab, "Terminal")

        # Connect tab change signal
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

    def create_terminal_container(self):
        """Create terminal output container"""
        self.terminal_container = QFrame()
        self.terminal_container.setFrameStyle(QFrame.Shape.Box)
        self.terminal_container.setLineWidth(1)

        layout = QVBoxLayout(self.terminal_container)
        layout.setContentsMargins(5, 5, 5, 5)

        # Terminal output area
        self.terminal_output_edit = QPlainTextEdit()
        self.terminal_output_edit.setReadOnly(True)
        self.terminal_output_edit.setFont(QFont("Consolas", 10))
        self.terminal_output_edit.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: none;
                padding: 10px;
            }
            QScrollBar:vertical {
                background-color: #2d2d2d;
                width: 12px;
            }
            QScrollBar::handle {
                background-color: #4a4a4a;
                min-height: 20px;
            }
            QScrollBar::add-line, QScrollBar::sub-line {
                background-color: #2d2d2d;
            }
        """)

        # Clear button
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.clear_terminal)
        clear_btn.setMaximumWidth(120)

        # Terminal header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Flask Server Output (Read-Only)"))
        header_layout.addStretch()
        header_layout.addWidget(clear_btn)

        layout.addLayout(header_layout)
        layout.addWidget(self.terminal_output_edit)

        # Initial message
        self.append_terminal("FreeKhana SIEM Terminal\n")
        self.append_terminal("=" * 50 + "\n\n")
        self.append_terminal("Server output will appear here when local backend is running.\n")

    def append_terminal(self, text):
        """Append text to terminal output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_text = f"[{timestamp}] {text}"
        self.terminal_output_edit.insertPlainText(formatted_text)
        self.terminal_output_edit.moveCursor(QTextCursor.MoveOperation.End)
        self.terminal_output += formatted_text

        # Auto-scroll to bottom
        scrollbar = self.terminal_output_edit.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output_edit.clear()
        self.append_terminal("Terminal cleared.\n")

    def show_terminal(self):
        """Switch to terminal tab"""
        self.tab_widget.setCurrentIndex(1)
        self.current_tab = "terminal"

    def show_webview(self):
        """Switch to webview tab"""
        self.tab_widget.setCurrentIndex(0)
        self.current_tab = "webview"

    def on_tab_changed(self, index):
        """Handle tab change"""
        if index == 0:
            self.current_tab = "webview"
        else:
            self.current_tab = "terminal"

    def start_local_backend(self):
        """Start the local Flask backend"""
        if not FLASK_AVAILABLE:
            QMessageBox.critical(self, "Error", "Flask backend is not available.")
            return

        self.append_terminal("\nStarting local Flask backend...\n")

        self.flask_server_running = True
        self.status_bar.showMessage("Starting offline backend...")
        self.start_local_btn.setEnabled(False)

        # Clear previous terminal output
        self.terminal_output_edit.clear()
        self.append_terminal("FreeKhana SIEM Terminal\n")
        self.append_terminal("=" * 50 + "\n\n")

        # Start Flask server in background thread
        self.flask_thread = FlaskServer()
        self.flask_thread.server_started.connect(self.on_flask_started)
        self.flask_thread.server_error.connect(self.on_flask_error)
        self.flask_thread.server_output.connect(self.on_flask_output)
        self.flask_thread.finished.connect(self.on_flask_finished)
        self.flask_thread.start()

    def stop_local_backend(self):
        """Stop the local Flask backend"""
        if not self.flask_server_running:
            QMessageBox.information(self, "Info", "Local backend is not running.")
            return

        self.append_terminal("\nStopping local Flask backend...\n")
        self.status_bar.showMessage("Stopping local backend...")
        self.stop_local_btn.setEnabled(False)

        # Switch to online backend first
        self.backend_combo.setCurrentText("Online (Cloud)")
        self.switch_to_online_backend()

        # Then stop the Flask server
        self.stop_flask_server()

    def on_backend_changed(self):
        """Handle backend selection change"""
        # Mark that user has made a manual selection
        self.initial_load = False

        backend_choice = self.backend_combo.currentData()

        if backend_choice == 'localhost':
            if "✓ Available" in self.local_status.text():
                self.switch_to_offline_backend()
            else:
                QMessageBox.warning(self, "Local Backend Unavailable",
                                  "Local backend is not running. Click 'Start Local Backend' to start it.")
                return
        elif backend_choice == 'online':
            if "✓ Available" in self.online_status.text():
                self.switch_to_online_backend()
            else:
                QMessageBox.warning(self, "Online Backend Unavailable",
                                  "Online backend is not accessible. Please check your internet connection.")
                return

    def create_webview_container(self):
        """Create container for WebView"""
        self.webview_container = QFrame()
        self.webview_container.setFrameStyle(QFrame.Shape.Box)
        self.webview_container.setLineWidth(1)

        layout = QVBoxLayout(self.webview_container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Create QWebEngineView widget
        self.webview_widget = QWebEngineView()
        self.webview_widget.setMinimumSize(800, 600)

        settings = self.webview_widget.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False)

        # Initial placeholder content
        self.webview_widget.setHtml("""
            <html>
            <body style="background-color: #1e293b; color: #94a3b8; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                <div style="text-align: center;">
                    <h2>FreeKhana SIEM Desktop</h2>
                    <p>WebView will load here...<br>Select a backend above to begin.</p>
                </div>
            </body>
            </html>
        """)

        layout.addWidget(self.webview_widget)

    def apply_modern_style(self):
        """Apply modern styling to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0f172a;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: #94a3b8;
            }
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:disabled {
                background-color: #475569;
                color: #94a3b8;
            }
            QComboBox {
                background-color: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border: none;
            }
            QStatusBar {
                background-color: #1e293b;
                color: #94a3b8;
            }
            QTabWidget::pane {
                background-color: #1e293b;
                border: 1px solid #334155;
            }
            QTabBar::tab {
                background-color: #0f172a;
                color: #94a3b8;
                padding: 8px 16px;
                border: 1px solid #334155;
            }
            QTabBar::tab:selected {
                background-color: #1e293b;
                color: #e2e8f0;
                border-bottom-color: #1e293b;
            }
        """)

    def cleanup_checker_threads(self):
        """Clean up any running checker threads"""
        for checker in self.backend_checkers[:]:
            if checker.isRunning():
                checker.stop()
                if not checker.wait(2000):
                    checker.terminate()
                    checker.wait(1000)
            self.backend_checkers.remove(checker)

    def remove_checker(self, checker):
        """Remove a finished checker from the list"""
        if checker in self.backend_checkers:
            self.backend_checkers.remove(checker)

    def check_backends(self):
        """Check availability of both backends"""
        self.status_bar.showMessage("Checking backend availability...")
        self.cleanup_checker_threads()

        self.local_status.setText("Offline: Checking...")
        self.online_status.setText("Online: Checking...")

        # Check localhost
        localhost_checker = BackendChecker('localhost', 'http://127.0.0.1:5000')
        localhost_checker.result_ready.connect(self.on_backend_check_result)
        localhost_checker.finished.connect(lambda: self.remove_checker(localhost_checker))
        self.backend_checkers.append(localhost_checker)
        localhost_checker.start()

        # Check online
        online_checker = BackendChecker('online', 'https://siem-backend.tanubhavj.workers.dev')
        online_checker.result_ready.connect(self.on_backend_check_result)
        online_checker.finished.connect(lambda: self.remove_checker(online_checker))
        self.backend_checkers.append(online_checker)
        online_checker.start()

    def on_backend_check_result(self, backend_type, available):
        """Handle backend check results"""
        if backend_type == 'localhost':
            ui_status = "✓ Available" if available else "✗ Not Available"
            color = "#22c55e" if available else "#ef4444"
            self.local_status.setText(f"Offline: {ui_status}")
            self.local_status.setStyleSheet(f"color: {color}; font-size: 11px;")

            if not self.flask_server_running:
                if available:
                    self.start_local_btn.setVisible(False)
                    self.stop_local_btn.setVisible(True)
                    self.stop_local_btn.setEnabled(True)
                    self.flask_server_running = True
                else:
                    self.start_local_btn.setVisible(True)
                    self.start_local_btn.setEnabled(True)
                    self.stop_local_btn.setVisible(False)
        else:
            ui_status = "✓ Available" if available else "✗ Not Available"
            color = "#22c55e" if available else "#ef4444"
            self.online_status.setText(f"Online: {ui_status}")
            self.online_status.setStyleSheet(f"color: {color}; font-size: 11px;")

        # Default to online backend only on initial load
        if self.initial_load and backend_type == 'online' and available:
            self.backend_combo.setCurrentText("Online (Cloud)")
            self.initial_load = False

    def switch_to_offline_backend(self):
        """Switch to offline (local) backend"""
        self.stop_flask_server()
        self.start_flask_server()
        self.switch_webview_backend('http://127.0.0.1:5000')

    def switch_to_online_backend(self):
        """Switch to online backend"""
        self.switch_webview_backend('https://freekhana-frontend.pages.dev')

    def on_webview_load_finished(self, success):
        """Handle WebView load finished"""
        if success:
            backend_name = "Offline" if self.current_backend and "127.0.0.1" in self.current_backend else "Online"
            self.status_bar.showMessage(f"Connected to {backend_name} backend")
        else:
            self.status_bar.showMessage("Failed to load web content")
            self.show_webview_error(f"Failed to load {self.current_backend}")

    def show_webview_error(self, message):
        """Show error message in WebView"""
        if self.webview_widget:
            error_html = f"""
                <html>
                <body style="background-color: #1e293b; color: #ef4444; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                    <div style="text-align: center;">
                        <h2>Error Loading Content</h2>
                        <p>{message}</p>
                        <p><small>Check your internet connection and backend availability.</small></p>
                    </div>
                </body>
                </html>
            """
            self.webview_widget.setHtml(error_html)

    def start_flask_server(self):
        """Start the Flask server"""
        if self.flask_thread and self.flask_thread.isRunning():
            self.on_flask_started()
            return

        self.append_terminal("\nInitializing Flask server...\n")

        self.flask_thread = FlaskServer()
        self.flask_thread.server_started.connect(self.on_flask_started)
        self.flask_thread.server_error.connect(self.on_flask_error)
        self.flask_thread.server_output.connect(self.on_flask_output)
        self.flask_thread.finished.connect(self.on_flask_finished)
        self.flask_thread.start()
        self.status_bar.showMessage("Starting offline backend...")

    def stop_flask_server(self):
        """Stop the Flask server"""
        if self.flask_thread:
            if self.flask_thread.isRunning():
                self.flask_thread.stop()
                if not self.flask_thread.wait(5000):
                    print("Warning: Flask thread did not stop cleanly")

            self.flask_thread = None

        self.flask_server_running = False
        self.status_bar.showMessage("Offline backend stopped")

        self.start_local_btn.setVisible(True)
        self.start_local_btn.setEnabled(True)
        self.stop_local_btn.setVisible(False)
        self.restart_local_btn.setEnabled(False)

    def restart_local_backend(self):
        """Restart the local Flask server"""
        if not self.flask_server_running:
            return

        self.append_terminal("\nRestarting local Flask backend...\n")
        self.status_bar.showMessage("Restarting local backend...")

        # Stop current server
        self.stop_flask_server()

        # Start new server after a short delay
        QTimer.singleShot(500, self.start_flask_server)

    def on_flask_started(self):
        """Handle Flask server startup"""
        self.flask_server_running = True
        self.status_bar.showMessage("Offline backend ready")
        self.append_terminal("\n✓ Flask server started successfully!\n")
        self.append_terminal("Server listening on http://127.0.0.1:5000\n")

        # Update button states
        self.start_local_btn.setVisible(False)
        self.stop_local_btn.setVisible(True)
        self.stop_local_btn.setEnabled(True)
        self.restart_local_btn.setEnabled(True)

        # Check availability again
        QTimer.singleShot(1000, lambda: self.check_backends())

    def on_flask_error(self, error):
        """Handle Flask server error"""
        self.append_terminal(f"\n✗ Flask server error: {error}\n")
        QMessageBox.critical(self, "Offline Backend Error", f"Failed to start offline backend:\n{error}")
        self.status_bar.showMessage("Offline backend failed")

        self.flask_server_running = False
        self.start_local_btn.setVisible(True)
        self.start_local_btn.setEnabled(True)
        self.stop_local_btn.setVisible(False)

    def on_flask_output(self, text):
        """Handle Flask server output"""
        # Filter out Werkzeug request logging for cleaner output
        if "127.0.0.1 - - [" in text:
            return
        if text.strip():
            self.append_terminal(text)

    def on_flask_finished(self):
        """Handle Flask server thread finished naturally"""
        if self.flask_server_running:
            self.flask_server_running = False
            self.status_bar.showMessage("Offline backend stopped")
            self.append_terminal("\nFlask server stopped.\n")

        self.flask_thread = None

        if not self.start_local_btn.isVisible():
            self.start_local_btn.setVisible(True)
            self.start_local_btn.setEnabled(True)
            self.stop_local_btn.setVisible(False)
            self.restart_local_btn.setEnabled(False)

    def switch_webview_backend(self, backend_url):
        """Switch WebView to the specified backend"""
        if backend_url == self.current_backend:
            return

        self.current_backend = backend_url
        self.status_bar.showMessage(f"Switching to {backend_url}...")

        if 'freekhana-frontend.pages.dev' in backend_url:
            webview_url = 'https://freekhana-frontend.pages.dev'
        else:
            webview_url = backend_url

        backend_name = "Offline" if "127.0.0.1" in backend_url else "Online"

        if self.webview_widget and WEBVIEW_AVAILABLE:
            self.webview_widget.loadFinished.connect(self.on_webview_load_finished)
            from PySide6.QtCore import QUrl
            self.webview_widget.load(QUrl(webview_url))
            self.status_bar.showMessage(f"Loading {backend_name} backend...")

    def resizeEvent(self, event):
        """Handle window resize"""
        super().resizeEvent(event)

    def closeEvent(self, event):
        """Handle application close"""
        print("Application closing - cleaning up resources...")

        self.cleanup_checker_threads()
        self.stop_flask_server()

        if self.webview_widget:
            try:
                self.webview_widget.loadFinished.disconnect(self.on_webview_load_finished)
            except:
                pass

        QTimer.singleShot(500, lambda: self.finish_close(event))

    def finish_close(self, event):
        """Finish the close operation"""
        print("Application cleanup complete")
        event.accept()


def main():
    """Main application entry point"""
    print("Starting FreeKhana SIEM Desktop...")
    print(f"Python version: {sys.version}")

    import os
    import platform

    os.environ['QT_LOGGING_RULES'] = 'qt.qthread=true'
    os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--disable-gpu --disable-software-rasterizer'

    if platform.system() == 'Windows':
        os.environ['QT_QPA_PLATFORM'] = 'windows:dpiawareness=0'

    app = QApplication(sys.argv)

    app.setApplicationName("FreeKhana SIEM Desktop")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("FreeKhana")

    force_online = '--online' in sys.argv

    window = FreeKhanaMainWindow()
    window.show()

    def cleanup():
        print("Qt aboutToQuit signal received - starting cleanup...")
        try:
            window.cleanup_checker_threads()
        except:
            pass
        try:
            window.stop_flask_server()
        except:
            pass
        try:
            if window.webview_widget:
                window.webview_widget.loadFinished.disconnect(window.on_webview_load_finished)
        except:
            pass
        print("Application cleanup complete")

    app.aboutToQuit.connect(cleanup)

    result = app.exec()
    print(f"Qt event loop exited with code: {result}")
    return result


if __name__ == '__main__':
    sys.exit(main())
