#!/bin/bash
# Build StealthShark as a distributable macOS DMG installer
# Users just drag StealthShark.app to Applications — that's it.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="StealthShark"
DMG_NAME="StealthShark-Installer"
VERSION="2.1.0"
VENV_DIR="$SCRIPT_DIR/build_venv"

echo ""
echo "🦈 Building StealthShark v${VERSION} DMG Installer"
echo "=================================================="
echo ""

# ── Step 1: Ensure build venv exists ──
if [ ! -d "$VENV_DIR" ]; then
    echo "📦 Creating build virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet pyinstaller PyQt6 psutil requests
    echo "✅ Build environment ready"
else
    echo "✅ Build environment found"
fi

PYINSTALLER="$VENV_DIR/bin/pyinstaller"

# ── Step 2: Clean previous builds ──
echo "🧹 Cleaning previous builds..."
rm -rf build/ dist/ "${DMG_NAME}.dmg"
echo "✅ Cleaned"

# ── Step 3: Build the .app bundle ──
echo ""
echo "🔨 Building ${APP_NAME}.app..."
echo "   This may take 1-2 minutes..."
echo ""

# Create spec inline with updated version
cat > "${APP_NAME}.spec" << EOF
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['multi_interface_shark_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('persistent_wireshark_monitor.py', '.'),
        ('stealth-shark-logo.png', '.'),
        ('INTEGRITY_HASHES.sha256', '.'),
    ],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'psutil',
        'requests',
        'plistlib',
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
    name='${APP_NAME}',
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
    name='${APP_NAME}',
)

app = BUNDLE(
    coll,
    name='${APP_NAME}.app',
    icon='stealth-shark-logo.icns',
    bundle_identifier='com.aimf.stealthshark',
    info_plist={
        'CFBundleName': '${APP_NAME}',
        'CFBundleDisplayName': 'StealthShark Network Monitor',
        'CFBundleVersion': '${VERSION}',
        'CFBundleShortVersionString': '${VERSION}',
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '10.13.0',
        'NSPrincipalClass': 'NSApplication',
        'CFBundlePackageType': 'APPL',
        'LSUIElement': False,
    },
)
EOF

"$PYINSTALLER" "${APP_NAME}.spec" --clean --noconfirm 2>&1 | tail -5

if [ ! -d "dist/${APP_NAME}.app" ]; then
    echo "❌ Build failed. Check output above."
    exit 1
fi

echo ""
echo "✅ ${APP_NAME}.app built successfully"
echo ""

# ── Step 4: Create the DMG ──
echo "💿 Creating DMG installer..."

DMG_DIR="dist/dmg_staging"
rm -rf "$DMG_DIR"
mkdir -p "$DMG_DIR"

# Copy app to staging
cp -R "dist/${APP_NAME}.app" "$DMG_DIR/"

# Create Applications symlink (for drag-to-install)
ln -s /Applications "$DMG_DIR/Applications"

# Create a README for the DMG
cat > "$DMG_DIR/README.txt" << 'READMEEOF'
🦈 StealthShark — Silent Network Capture

INSTALLATION:
  Drag StealthShark.app to the Applications folder.
  That's it! Double-click to launch.

FIRST LAUNCH:
  A setup wizard will guide you through permissions
  and settings. Takes under 1 minute.

MENU BAR:
  StealthShark runs in your menu bar. Click the
  icon to open the dashboard or control captures.

MORE INFO:
  https://github.com/aimarketingflow/stealthshark
  https://aimarketingflow.com

© 2026 AI Marketing Flow
READMEEOF

# Create DMG using hdiutil
hdiutil create \
    -volname "${APP_NAME}" \
    -srcfolder "$DMG_DIR" \
    -ov \
    -format UDZO \
    "dist/${DMG_NAME}.dmg"

# Clean up staging
rm -rf "$DMG_DIR"

echo ""
echo "=================================================="
echo "✅ BUILD COMPLETE!"
echo ""
echo "📦 App:  dist/${APP_NAME}.app"
echo "💿 DMG:  dist/${DMG_NAME}.dmg"
echo ""
echo "File sizes:"
du -sh "dist/${APP_NAME}.app"
du -sh "dist/${DMG_NAME}.dmg"
echo ""
echo "📋 To install locally:"
echo "   cp -R dist/${APP_NAME}.app /Applications/"
echo ""
echo "📋 To distribute:"
echo "   Share dist/${DMG_NAME}.dmg — users just drag to Applications"
echo ""
echo "🦈 Done!"
