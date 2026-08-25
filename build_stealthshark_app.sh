#!/bin/bash
# Build StealthShark as a standalone macOS application
# This creates a self-contained .app bundle with all dependencies

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "🦈 Building StealthShark Standalone Application"
echo "================================================"
echo ""

# Activate the virtual environment
source "$SCRIPT_DIR/stealthshark_env/bin/activate"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/ dist/ StealthShark.spec
echo "✅ Cleaned"
echo ""

# Create PyInstaller spec file
echo "📝 Creating PyInstaller spec file..."
cat > StealthShark.spec << 'EOF'
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['multi_interface_shark_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('persistent_wireshark_monitor.py', '.'),
        ('stealth-shark-logo.png', '.'),
    ],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'psutil',
        'requests',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='StealthShark',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='StealthShark',
)

app = BUNDLE(
    coll,
    name='StealthShark.app',
    icon='stealth-shark-logo.icns',
    bundle_identifier='com.aimf.stealthshark',
    info_plist={
        'CFBundleName': 'StealthShark',
        'CFBundleDisplayName': 'StealthShark Network Monitor',
        'CFBundleVersion': '3.0.0',
        'CFBundleShortVersionString': '3.0.0',
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '10.13.0',
        'NSPrincipalClass': 'NSApplication',
        'CFBundlePackageType': 'APPL',
    },
)
EOF

echo "✅ Spec file created"
echo ""

# Build the application
echo "🔨 Building standalone application..."
echo "This may take a few minutes..."
echo ""

pyinstaller StealthShark.spec --clean --noconfirm

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build completed successfully!"
    echo ""
    echo "📦 Standalone app location:"
    echo "   $SCRIPT_DIR/dist/StealthShark.app"
    echo ""
    echo "📋 Next steps:"
    echo "   1. Test: open dist/StealthShark.app"
    echo "   2. Move to Applications: mv dist/StealthShark.app /Applications/"
    echo "   3. Create desktop alias: ln -s /Applications/StealthShark.app ~/Desktop/"
    echo ""
    echo "🦈 The app is now self-contained with all dependencies!"
else
    echo ""
    echo "❌ Build failed. Check the output above for errors."
    exit 1
fi
