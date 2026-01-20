#!/usr/bin/env python3
"""
Setup and run script for FreeKhana SIEM GUI Tool
"""

import subprocess
import sys
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing dependencies...")

    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])

        # Install requirements
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def run_application():
    """Run the SIEM GUI application"""
    print("🚀 Starting FreeKhana SIEM GUI...")

    try:
        # Add src to path and run
        src_dir = Path(__file__).parent / "src"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(src_dir)

        subprocess.run([sys.executable, str(src_dir / "main.py")], env=env, check=True)

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to run application: {e}")
        return False
    except KeyboardInterrupt:
        print("\n👋 Application closed by user")
        return True

    return True

def main():
    print("🔍 FreeKhana SIEM GUI Tool Setup")
    print("=" * 40)

    # Check Python version
    check_python_version()

    # Check if dependencies are installed
    try:
        import PySide6
        import pandas
        import numpy
        import sklearn
        print("✅ Dependencies already installed")
        deps_installed = True
    except ImportError:
        print("⚠️  Dependencies not found")
        deps_installed = False

    # Install dependencies if needed
    if not deps_installed:
        if not install_dependencies():
            print("\n💡 To install manually: pip install -r requirements.txt")
            sys.exit(1)

    # Run the application
    print("\n" + "=" * 40)
    success = run_application()

    if success:
        print("👋 Thank you for using FreeKhana SIEM!")
    else:
        print("❌ Application exited with errors")

if __name__ == "__main__":
    main()