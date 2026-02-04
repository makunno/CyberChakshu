"""FreeKhana SIEM Browser - Embedded webview to online frontend"""

import sys

from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout
from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings


class FreeKhanaBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FreeKhana SIEM")
        self.setGeometry(100, 100, 1400, 900)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.webview = QWebEngineView()
        self.webview.setUrl(QUrl("https://freekhana-frontend.pages.dev"))

        settings = self.webview.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

        layout.addWidget(self.webview)
        self.statusBar().showMessage("Loading FreeKhana SIEM...")

        self.webview.loadFinished.connect(
            lambda _: self.statusBar().showMessage("Connected to FreeKhana SIEM")
        )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("FreeKhana SIEM")
    app.setApplicationVersion("2.0.0")

    window = FreeKhanaBrowser()
    window.show()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
