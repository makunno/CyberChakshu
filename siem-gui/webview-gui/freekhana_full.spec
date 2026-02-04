# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for FreeKhana SIEM Full (Browser + Flask Backend)
Bundles frontend files and Flask backend
"""

import os
import sys
from pathlib import Path

block_cipher = None

# Get the directory containing this spec file
SPEC_DIR = Path(__file__).parent.resolve()

# Collect all files from static folder
def get_static_files():
    """Collect all static files to include"""
    files = []
    static_dir = SPEC_DIR / 'static'
    
    if static_dir.exists():
        for root, dirs, filenames in os.walk(static_dir):
            for filename in filenames:
                filepath = Path(root) / filename
                # Calculate relative path from static_dir
                rel_path = filepath.relative_to(static_dir)
                files.append((str(filepath), str(rel_path)))
    
    return files

static_files = get_static_files()
print(f"Including {len(static_files)} static files")

a = Analysis(
    ['main.py'],
    pathex=[str(SPEC_DIR)],
    binaries=[],
    datas=[
        # Include static folder contents
        (str(SPEC_DIR / 'static'), 'static'),
    ],
    hiddenimports=[
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtWidgets',
        'PySide6.QtGui',
        'PySide6.QtWebEngineWidgets',
        'PySide6.QtWebEngineCore',
        'flask',
        'werkzeug',
        'requests',
        'sklearn',
        'numpy',
        'scipy',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'test',
        'unittest',
        'pydoc',
        'doctest',
        'pytest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FreeKhana-Full',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)
