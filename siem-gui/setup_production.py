#!/usr/bin/env python3
"""
FreeKhana SIEM GUI Tool - Production Setup
Creates desktop shortcuts, configures settings, and sets up the application for end users.
"""

import sys
import os
import json
import shutil
from pathlib import Path
from typing import Dict, Any

class SIEMSetup:
    """Production setup for FreeKhana SIEM GUI"""

    def __init__(self):
        self.app_name = "FreeKhana SIEM"
        self.config_dir = Path.home() / ".freekhana_siem"
        self.desktop_dir = self._get_desktop_dir()
        self.config_file = self.config_dir / "config.json"

    def _get_desktop_dir(self) -> Path:
        """Get the desktop directory for the current platform"""
        if sys.platform == "win32":
            return Path.home() / "Desktop"
        elif sys.platform == "darwin":  # macOS
            return Path.home() / "Desktop"
        else:  # Linux
            return Path.home() / "Desktop"

    def create_config(self, settings: Dict[str, Any]):
        """Create configuration file"""
        self.config_dir.mkdir(exist_ok=True)

        config = {
            "app_name": self.app_name,
            "version": "1.0.0",
            "settings": settings,
            "installation": {
                "date": str(Path(__file__).parent.stat().st_mtime),
                "platform": sys.platform,
                "python_version": sys.version
            }
        }

        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration created at: {self.config_file}")

    def create_desktop_shortcut(self):
        """Create desktop shortcut"""
        try:
            if sys.platform == "win32":
                self._create_windows_shortcut()
            elif sys.platform == "darwin":
                self._create_macos_shortcut()
            else:
                self._create_linux_shortcut()
            print("✅ Desktop shortcut created")
        except Exception as e:
            print(f"⚠️  Failed to create desktop shortcut: {e}")

    def _create_windows_shortcut(self):
        """Create Windows .lnk file"""
        shortcut_path = self.desktop_dir / f"{self.app_name}.lnk"

        # For Windows, we'll create a batch file instead of complex .lnk creation
        batch_content = f'''@echo off
cd /d "{Path(__file__).parent}"
python run.py
pause
'''

        batch_path = self.desktop_dir / f"{self.app_name}.bat"
        with open(batch_path, 'w') as f:
            f.write(batch_content)

    def _create_macos_shortcut(self):
        """Create macOS application shortcut"""
        # Create a simple shell script
        script_content = f'''#!/bin/bash
cd "{Path(__file__).parent}"
python3 run.py
'''

        script_path = self.desktop_dir / f"{self.app_name}.command"
        with open(script_path, 'w') as f:
            f.write(script_content)

        # Make executable
        os.chmod(script_path, 0o755)

    def _create_linux_shortcut(self):
        """Create Linux .desktop file"""
        desktop_content = f'''[Desktop Entry]
Version=1.0
Type=Application
Name={self.app_name}
Comment=Security Information and Event Management Tool
Exec=python3 {Path(__file__).parent / "run.py"}
Icon={Path(__file__).parent / "resources" / "icon.png"}
Terminal=false
Categories=Security;System;Monitor;
'''

        desktop_path = self.desktop_dir / f"{self.app_name}.desktop"
        with open(desktop_path, 'w') as f:
            f.write(desktop_content)

        # Make executable
        os.chmod(desktop_path, 0o755)

    def create_start_menu_entry(self):
        """Create Start Menu entry (Windows only)"""
        if sys.platform != "win32":
            return

        try:
            start_menu_dir = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            start_menu_dir.mkdir(parents=True, exist_ok=True)

            batch_content = f'''@echo off
cd /d "{Path(__file__).parent}"
python run.py
pause
'''

            batch_path = start_menu_dir / f"{self.app_name}.bat"
            with open(batch_path, 'w') as f:
                f.write(batch_content)

            print("✅ Start Menu entry created")
        except Exception as e:
            print(f"⚠️  Failed to create Start Menu entry: {e}")

    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.config_dir,
            self.config_dir / "logs",
            self.config_dir / "exports",
            self.config_dir / "cache"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

        print(f"✅ Application directories created in: {self.config_dir}")

    def run_setup(self):
        """Run the complete setup process"""
        print(f"🚀 Setting up {self.app_name}")
        print("=" * 50)

        # Get user preferences
        settings = self._get_user_settings()

        # Create directories
        self.setup_directories()

        # Create configuration
        self.create_config(settings)

        # Create shortcuts
        self.create_desktop_shortcut()

        if sys.platform == "win32":
            self.create_start_menu_entry()

        print("\n" + "=" * 50)
        print("✅ Setup Complete!")
        print(f"\n🎯 {self.app_name} is ready to use!")
        print(f"   📁 Installed in: {Path(__file__).parent}")
        print(f"   ⚙️  Config: {self.config_file}")
        print(f"   🖥️  Desktop shortcut created")

        if settings.get("auto_start", False):
            print("   🔄 Auto-start enabled")

        print("
📖 Run the application:"        print(f"   python run.py")
        print("
🎉 Happy analyzing!"    def _get_user_settings(self) -> Dict[str, Any]:
        """Get user settings through interactive prompts"""
        settings = {}

        print("\n⚙️  Configuration Setup:")

        # Theme preference
        while True:
            theme = input("Choose theme (dark/light) [dark]: ").strip().lower()
            if theme in ["", "dark", "light"]:
                settings["theme"] = theme or "dark"
                break
            print("Please enter 'dark' or 'light'")

        # Auto-save preference
        while True:
            autosave = input("Enable auto-save of analysis results? (y/n) [y]: ").strip().lower()
            if autosave in ["", "y", "yes", "n", "no"]:
                settings["auto_save"] = autosave in ["", "y", "yes"]
                break
            print("Please enter 'y' or 'n'")

        # History size
        while True:
            try:
                history_size = input("Maximum history entries to keep [20]: ").strip()
                if history_size == "":
                    settings["max_history"] = 20
                else:
                    settings["max_history"] = int(history_size)
                break
            except ValueError:
                print("Please enter a valid number")

        # Default log directory
        default_log_dir = input(f"Default log directory [{Path.home() / 'logs'}]: ").strip()
        if default_log_dir == "":
            settings["default_log_dir"] = str(Path.home() / "logs")
        else:
            settings["default_log_dir"] = default_log_dir

        # Performance settings
        while True:
            ml_enabled = input("Enable ML analysis features? (y/n) [y]: ").strip().lower()
            if ml_enabled in ["", "y", "yes", "n", "no"]:
                settings["ml_enabled"] = ml_enabled in ["", "y", "yes"]
                break
            print("Please enter 'y' or 'n'")

        return settings

def main():
    """Main setup function"""
    try:
        setup = SIEMSetup()
        setup.run_setup()
    except KeyboardInterrupt:
        print("\n\n👋 Setup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()