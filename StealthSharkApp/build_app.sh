#!/bin/bash
# Build StealthShark Swift app as a macOS .app bundle
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="StealthShark"
APP_BUNDLE="$SCRIPT_DIR/dist/${APP_NAME}.app"
ICON_SOURCE="$PROJECT_DIR/stealth-shark-logo.icns"

echo "Building StealthShark Swift App..."
echo "==================================="

# Build release
cd "$SCRIPT_DIR"
swift build -c release 2>&1 | tail -5

BINARY="$SCRIPT_DIR/.build/release/StealthShark"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed — binary not found"
    exit 1
fi

echo "Binary size: $(du -h "$BINARY" | cut -f1)"

# Create .app bundle structure
echo "Packaging .app bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy binary
cp "$BINARY" "$APP_BUNDLE/Contents/MacOS/StealthShark"

# Copy icon
if [ -f "$ICON_SOURCE" ]; then
    cp "$ICON_SOURCE" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    echo "  Icon: included"
fi

# Create Info.plist
cat > "$APP_BUNDLE/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>StealthShark</string>
    <key>CFBundleIdentifier</key>
    <string>com.aimf.stealthshark</string>
    <key>CFBundleName</key>
    <string>StealthShark</string>
    <key>CFBundleDisplayName</key>
    <string>StealthShark Network Monitor</string>
    <key>CFBundleVersion</key>
    <string>3.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>3.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>StealthShark monitors local network interfaces for security analysis.</string>
    <key>NSAppleEventsUsageDescription</key>
    <string>StealthShark needs access to control system processes for network capture.</string>
</dict>
</plist>
PLIST

# Create PkgInfo
echo -n "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

# Ad-hoc sign
codesign --force --deep --sign - "$APP_BUNDLE" 2>/dev/null || true

echo ""
echo "BUILD COMPLETE"
echo "  App: $APP_BUNDLE"
echo "  Size: $(du -sh "$APP_BUNDLE" | cut -f1)"
echo ""
echo "Install:"
echo "  cp -R \"$APP_BUNDLE\" /Applications/"
echo "  open /Applications/StealthShark.app"
