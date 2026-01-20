#!/usr/bin/env python3
"""
FreeKhana SIEM GUI Tool - Setup Script
"""

import sys
import os
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ ERROR: Python 3.8+ is required")
        sys.exit(1)
    print("✅ OK: Python 3.8+ detected")

def check_dependencies():
    """Check which dependencies are available"""
    deps = {
        'PySide6': 'PySide6.QtWidgets',
        'pandas': 'pandas',
        'numpy': 'numpy',
        'scikit-learn': 'sklearn.ensemble',
        'matplotlib': 'matplotlib.pyplot'
    }

    available = {}
    for name, module in deps.items():
        try:
            __import__(module)
            available[name] = True
            print(f"✅ OK: {name} is available")
        except ImportError:
            available[name] = False
            print(f"⚠️  MISSING: {name} - will use fallback mode")

    return available

def install_dependencies():
    """Attempt to install missing dependencies"""
    print("\n📦 Attempting to install dependencies...")

    try:
        # Upgrade pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL)

        # Install PySide6 first (most important)
        print("Installing PySide6 (GUI framework)...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PySide6"], stdout=subprocess.DEVNULL)

        # Install other dependencies
        requirements = [
            "pandas",
            "numpy",
            "scikit-learn",
            "matplotlib",
            "seaborn"
        ]

        for req in requirements:
            print(f"Installing {req}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", req], stdout=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                print(f"⚠️  Failed to install {req} - will use fallback mode")

        print("✅ Dependencies installation completed")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("\n💡 Manual installation:")
        print("   pip install PySide6 pandas numpy scikit-learn matplotlib seaborn")
        return False

def main():
    """Main setup function"""
    print("🔍 FreeKhana SIEM GUI Tool Setup")
    print("=" * 50)

    # Check Python version
    check_python_version()

    # Check existing dependencies
    deps_available = check_dependencies()

    # Check if we can run
    if not deps_available.get('PySide6', False):
        print("\n⚠️  PySide6 (GUI framework) is required but not installed.")
        choice = input("Install dependencies automatically? (y/N): ").lower().strip()

        if choice == 'y':
            if not install_dependencies():
                print("\n❌ Setup failed. Please install dependencies manually.")
                sys.exit(1)
        else:
            print("\n💡 To install manually:")
            print("   pip install PySide6 pandas numpy scikit-learn matplotlib seaborn")
            print("   Then run: python run.py")
            sys.exit(0)

    # Re-check dependencies
    deps_available = check_dependencies()

    if deps_available.get('PySide6', False):
        print("\n🚀 Ready to run!")
        print("   python run.py")
        print("\nOr run directly:")
        print("   python src/main.py")

        # Test import
        try:
            from src.main import ML_AVAILABLE
            print(f"\n🤖 ML Features: {'Available' if ML_AVAILABLE else 'Limited (install scikit-learn)'}")
        except ImportError as e:
            print(f"\n⚠️  Import test failed: {e}")

    else:
        print("\n❌ Cannot run without PySide6 GUI framework.")
        print("   pip install PySide6")
        sys.exit(1)

if __name__ == "__main__":
    main()