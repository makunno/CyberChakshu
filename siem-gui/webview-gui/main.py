"""Main PyWebView Desktop Application"""

import webview
import threading
import sys
from pathlib import Path

# Import Flask API
from api.app import app

# Flask API will run in separate thread
def start_api():
    """Start Flask API in background thread"""
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)


def main():
    """Start PyWebView application"""
    print("Starting FreeKhana SIEM Desktop...")
    print("Initializing backend API...")

    # Start Flask API in background thread
    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()

    # Wait a moment for API to start
    import time
    time.sleep(2)

    print("Backend API ready at http://127.0.0.1:5000")
    print("Loading UI...")

    # Create PyWebView window
    window = webview.create_window(
        title='FreeKhana SIEM',
        url='http://127.0.0.1:5000',
        width=1400,
        height=900,
        resizable=True,
        fullscreen=False,
        confirm_close=True,
        background_color='#0f0f23',
        text_select=True,
    )

    # Set window icon if available
    icon_path = Path(__file__).parent.parent / 'icon.ico'
    if icon_path.exists():
        window.icon = str(icon_path)

    # Show window and run
    webview.start(debug=False)


if __name__ == '__main__':
    main()
