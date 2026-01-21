#!/usr/bin/env python3
"""Alternative FreeKhana SIEM Desktop - Browser-based fallback"""

import sys
import os
import requests
import threading
import time
import webbrowser
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# PySide6 imports (without WebEngine)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QGroupBox, QStatusBar,
    QMessageBox, QProgressBar, QFrame, QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QPalette, QColor, QIcon

# Flask API imports (for local backend) - lazy loading
FLASK_AVAILABLE = True  # Assume available, check at runtime


class BackendChecker(QThread):
    """Thread to check backend availability"""
    result_ready = Signal(str, bool)  # backend_type, available

    def __init__(self, backend_type, url):
        super().__init__()
        self.backend_type = backend_type
        self.url = url
        self._stopping = False

    def run(self):
        try:
            if self.backend_type == 'localhost':
                # Check local Flask API
                print(f"Checking localhost backend: {self.url}/parsers")
                response = requests.get(f'{self.url}/parsers', timeout=3)
                available = response.status_code == 200
                print(f"Localhost check result: {available}")
            else:  # online
                # Check online backend API (not frontend)
                print(f"Checking online backend: {self.url}/parsers")
                response = requests.get(f'{self.url}/parsers', timeout=5)
                available = response.status_code == 200
                print(f"Online check result: {available}")
        except Exception as e:
            print(f"Backend check failed for {self.backend_type}: {e}")
            available = False

        print(f"Emitting result for {self.backend_type}: {available}")
        self.result_ready.emit(self.backend_type, available)

    def stop(self):
        """Stop the checker thread"""
        self._stopping = True


class FlaskServer(QThread):
    """Thread to run Flask server"""
    server_started = Signal()
    server_error = Signal(str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._shutdown = False
        self.server = None

    def run(self):
        try:
            # Import Flask app here to avoid circular imports
            from api.app import app as flask_app
            self.running = True

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
            if not self._shutdown:  # Only emit error if not shutting down
                self.server_error.emit(str(e))
        finally:
            self.running = False
            if self.server:
                try:
                    self.server.shutdown()
                except:
                    pass

    def stop(self):
        """Stop the Flask server"""
        self._shutdown = True
        self.running = False

        # Shutdown the server
        if self.server:
            try:
                self.server.shutdown()
                # Give server time to shutdown gracefully
                import time
                time.sleep(0.5)
            except:
                pass

        # Terminate the thread if still running
        if self.isRunning():
            self.terminate()
            if not self.wait(3000):  # Wait up to 3 seconds for clean shutdown
                print("Warning: Flask thread did not terminate cleanly")


class FreeKhanaMainWindow(QMainWindow):
    """Main application window with browser-based fallback"""

    def __init__(self):
        super().__init__()
        self.current_backend = None
        self.flask_thread = None
        self.flask_server_running = False  # Track server state independently
        self.backend_checkers = []  # Track active checker threads

        print("Initializing UI...")
        self.init_ui()
        print("UI initialized, checking backends...")
        self.check_backends()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FreeKhana SIEM Desktop (Browser Mode)")
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(800, 600)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)

        # Backend selection panel (top)
        self.create_backend_panel()
        main_layout.addWidget(self.backend_panel)

        # Browser info panel (middle)
        self.create_browser_panel()
        main_layout.addWidget(self.browser_panel, 1)  # Stretch factor 1

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
        self.backend_combo.addItem("Auto-Detect", "auto")
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
        self.stop_local_btn.setVisible(False)  # Initially hidden
        layout.addWidget(self.stop_local_btn)

        layout.addStretch()

    def create_browser_panel(self):
        """Create the browser info panel"""
        self.browser_panel = QFrame()
        self.browser_panel.setFrameStyle(QFrame.Shape.Box)
        self.browser_panel.setLineWidth(1)

        layout = QVBoxLayout(self.browser_panel)

        # Info label
        info_label = QLabel("Browser-Based Mode")
        info_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #3b82f6;")
        layout.addWidget(info_label)

        # Description
        desc_text = QTextEdit()
        desc_text.setPlainText("""
FreeKhana SIEM Desktop is running in Browser Mode due to graphics compatibility issues.

The application will open your system's default web browser to access the SIEM interface.

Features:
• Automatic backend detection and switching
• Real-time status monitoring
• Seamless browser integration
• Full SIEM functionality through web interface

Click "Open in Browser" to launch the SIEM interface.
        """)
        desc_text.setReadOnly(True)
        desc_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e293b;
                color: #e2e8f0;
                border: none;
                font-family: 'Segoe UI', sans-serif;
            }
        """)
        layout.addWidget(desc_text)

        # Open browser button
        self.open_browser_btn = QPushButton("Open in Browser")
        self.open_browser_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        self.open_browser_btn.clicked.connect(self.open_in_browser)
        self.open_browser_btn.setEnabled(False)
        layout.addWidget(self.open_browser_btn)

        layout.addStretch()

    def apply_modern_style(self):
        """Apply modern styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0f172a;
                color: #e2e8f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #374151;
                border-radius: 8px;
                margin-top: 1ex;
                background-color: #1e293b;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
                color: #3b82f6;
            }
            QLabel {
                color: #e2e8f0;
            }
            QComboBox {
                background-color: #374151;
                color: #e2e8f0;
                border: 1px solid #4b5563;
                border-radius: 4px;
                padding: 4px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 4px solid #e2e8f0;
                margin-right: 8px;
            }
            QPushButton {
                background-color: #374151;
                color: #e2e8f0;
                border: 1px solid #4b5563;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #4b5563;
            }
            QPushButton:disabled {
                background-color: #1f2937;
                color: #6b7280;
            }
        """)

    def cleanup_checker_threads(self):
        """Clean up any running checker threads"""
        for checker in self.backend_checkers[:]:  # Copy list to avoid modification issues
            if checker.isRunning():
                checker.stop()  # Signal thread to stop
                if not checker.wait(2000):  # Wait 2 seconds for graceful stop
                    checker.terminate()  # Force terminate if needed
                    checker.wait(1000)  # Wait 1 more second
            self.backend_checkers.remove(checker)

    def remove_checker(self, checker):
        """Remove a finished checker from the list"""
        if checker in self.backend_checkers:
            self.backend_checkers.remove(checker)

    def check_backends(self):
        """Check availability of both backends"""
        print("check_backends() called")
        self.status_bar.showMessage("Checking backend availability...")

        # Clean up any existing checker threads
        self.cleanup_checker_threads()

        # Reset status
        self.local_status.setText("Offline: Checking...")
        self.online_status.setText("Online: Checking...")

        # Check localhost
        localhost_checker = BackendChecker('localhost', 'http://127.0.0.1:5000')
        localhost_checker.result_ready.connect(self.on_backend_check_result)
        localhost_checker.finished.connect(lambda: self.remove_checker(localhost_checker))
        self.backend_checkers.append(localhost_checker)
        localhost_checker.start()

        # Check online (check backend API availability, but load frontend in browser)
        online_checker = BackendChecker('online', 'https://siem-backend.tanubhavj.workers.dev')
        online_checker.result_ready.connect(self.on_backend_check_result)
        online_checker.finished.connect(lambda: self.remove_checker(online_checker))
        self.backend_checkers.append(online_checker)
        online_checker.start()

    def on_backend_check_result(self, backend_type, available):
        """Handle backend check results"""
        print(f"Received backend check result: {backend_type} = {available}")

        if backend_type == 'localhost':
            status = "Available" if available else "Not Available"
            ui_status = "✓ Available" if available else "✗ Not Available"
            color = "#22c55e" if available else "#ef4444"
            self.local_status.setText(f"Offline: {ui_status}")
            self.local_status.setStyleSheet(f"color: {color}; font-size: 11px;")
            # Only update button states if we're not in the middle of starting/stopping
            # The button states are primarily controlled by flask_server_running flag
            if not self.flask_server_running:
                if available:
                    # Server is running but we didn't start it (external server)
                    self.start_local_btn.setVisible(False)
                    self.stop_local_btn.setVisible(True)
                    self.stop_local_btn.setEnabled(True)
                    self.flask_server_running = True  # Sync the flag
                else:
                    # Server is not running
                    self.start_local_btn.setVisible(True)
                    self.start_local_btn.setEnabled(True)
                    self.stop_local_btn.setVisible(False)
        else:  # online
            status = "Available" if available else "Not Available"
            ui_status = "✓ Available" if available else "✗ Not Available"
            color = "#22c55e" if available else "#ef4444"
            self.online_status.setText(f"Online: {ui_status}")
            self.online_status.setStyleSheet(f"color: {color}; font-size: 11px;")
            print(f"Updated online status: {status}")

        # Auto-select best available backend
        self.auto_select_backend()

    def auto_select_backend(self):
        """Automatically select the best available backend"""
        localhost_text = self.local_status.text()
        online_text = self.online_status.text()

        if "✓ Available" in localhost_text:
            self.backend_combo.setCurrentText("Offline (Local)")
        elif "✓ Available" in online_text:
            self.backend_combo.setCurrentText("Online (Cloud)")
        else:
            self.status_bar.showMessage("No backends available - please check your connection")

    def on_backend_changed(self):
        """Handle backend selection change"""
        backend_choice = self.backend_combo.currentData()

        if backend_choice == 'auto':
            self.auto_select_backend()
            return

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

    def start_local_backend(self):
        """Start the local Flask backend"""
        if not FLASK_AVAILABLE:
            QMessageBox.critical(self, "Error", "Flask backend is not available.")
            return

        self.flask_server_running = True  # Set flag immediately when starting
        self.status_bar.showMessage("Starting offline backend...")
        self.start_local_btn.setEnabled(False)

        # Start Flask server in background thread
        self.flask_thread = FlaskServer()
        self.flask_thread.server_started.connect(self.on_flask_started)
        self.flask_thread.server_error.connect(self.on_flask_error)
        self.flask_thread.finished.connect(self.on_flask_finished)
        self.flask_thread.start()

    def stop_local_backend(self):
        """Stop the local Flask backend"""
        if not self.flask_server_running:
            QMessageBox.information(self, "Info", "Local backend is not running.")
            return

        self.status_bar.showMessage("Switching to online backend and stopping local server...")
        self.stop_local_btn.setEnabled(False)

        # Switch to online backend first
        self.backend_combo.setCurrentText("Online (Cloud)")
        self.switch_to_online_backend()

        # Then stop the Flask server
        self.stop_flask_server()

    def switch_to_offline_backend(self):
        """Switch to offline (local) backend"""
        # Stop any existing Flask server
        self.stop_flask_server()

        # Start Flask server
        self.start_flask_server()

        # Update UI for local backend
        self.current_backend = 'http://127.0.0.1:5000'
        self.status_bar.showMessage("Offline backend ready - click 'Open in Browser'")
        self.open_browser_btn.setEnabled(True)

    def switch_to_online_backend(self):
        """Switch to online backend"""
        # Update UI for online backend
        self.current_backend = 'https://freekhana-frontend.pages.dev'
        self.status_bar.showMessage("Online backend ready - click 'Open in Browser'")
        self.open_browser_btn.setEnabled(True)

    def open_in_browser(self):
        """Open the current backend URL in system browser"""
        if self.current_backend:
            try:
                webbrowser.open(self.current_backend)
                backend_name = "Offline" if "127.0.0.1" in self.current_backend else "Online"
                self.status_bar.showMessage(f"Opened {backend_name} backend in browser")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open browser: {e}")
        else:
            QMessageBox.warning(self, "No Backend Selected", "Please select a backend first.")

    def start_flask_server(self):
        """Start the Flask server"""
        if self.flask_thread and self.flask_thread.isRunning():
            # Server already running
            self.on_flask_started()
            return

        self.flask_thread = FlaskServer()
        self.flask_thread.server_started.connect(self.on_flask_started)
        self.flask_thread.server_error.connect(self.on_flask_error)
        self.flask_thread.finished.connect(self.on_flask_finished)  # Connect finished signal
        self.flask_thread.start()
        self.status_bar.showMessage("Starting offline backend...")

    def stop_flask_server(self):
        """Stop the Flask server"""
        if self.flask_thread:
            if self.flask_thread.isRunning():
                self.flask_thread.stop()
                # Wait for thread to finish (with timeout)
                if not self.flask_thread.wait(5000):  # 5 second timeout
                    print("Warning: Flask thread did not stop cleanly")

            # Clean up thread reference
            self.flask_thread = None

        # Immediately update server state and UI
        self.flask_server_running = False
        self.status_bar.showMessage("Offline backend stopped")

        # Update button states immediately
        self.start_local_btn.setVisible(True)
        self.start_local_btn.setEnabled(True)
        self.stop_local_btn.setVisible(False)

    def on_flask_started(self):
        """Handle Flask server startup"""
        self.flask_server_running = True
        self.status_bar.showMessage("Offline backend ready")
        # Update button states
        self.start_local_btn.setVisible(False)
        self.stop_local_btn.setVisible(True)
        self.stop_local_btn.setEnabled(True)
        # Check availability again
        QTimer.singleShot(1000, lambda: self.check_backends())

    def on_flask_error(self, error):
        """Handle Flask server error"""
        QMessageBox.critical(self, "Offline Backend Error", f"Failed to start offline backend:\n{error}")
        self.status_bar.showMessage("Offline backend failed")

    def on_flask_finished(self):
        """Handle Flask server thread finished naturally"""
        # Only update state if server was running (not if it was manually stopped)
        if self.flask_server_running:
            self.flask_server_running = False
            self.status_bar.showMessage("Offline backend stopped")

        self.flask_thread = None

        # Update button states (only if not already updated by stop_flask_server)
        if not self.start_local_btn.isVisible():
            self.start_local_btn.setVisible(True)
            self.start_local_btn.setEnabled(True)
            self.stop_local_btn.setVisible(False)

    def closeEvent(self, event):
        """Handle application close"""
        print("Application closing - cleaning up resources...")

        # Clean up checker threads first
        self.cleanup_checker_threads()
        print("Checker threads cleaned up")

        # Stop Flask server
        self.stop_flask_server()
        print("Flask server stopped")

        # Give a moment for cleanup
        QTimer.singleShot(500, lambda: self.finish_close(event))

    def finish_close(self, event):
        """Finish the close operation after cleanup"""
        print("Application cleanup complete")
        event.accept()


def main():
    """Main application entry point"""
    print("Starting FreeKhana SIEM Desktop (Browser Mode)...")
    print(f"Python version: {sys.version}")

    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName("FreeKhana SIEM Desktop")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("FreeKhana")

    # Check for command line arguments
    force_online = '--online' in sys.argv

    if force_online:
        print("Forcing online backend as requested...")

    print("Creating main window...")
    # Create and show main window
    window = FreeKhanaMainWindow()
    window.show()
    print("Main window shown")

    # Handle cleanup on exit
    def cleanup():
        print("Qt aboutToQuit signal received - starting cleanup...")
        try:
            window.cleanup_checker_threads()
            print("Checker threads cleaned up")
        except:
            pass

        try:
            window.stop_flask_server()
            print("Flask server stopped")
        except:
            pass

        print("Application cleanup complete")

    app.aboutToQuit.connect(cleanup)

    print("Starting Qt event loop...")
    result = app.exec()
    print(f"Qt event loop exited with code: {result}")
    return result


if __name__ == '__main__':
    sys.exit(main())