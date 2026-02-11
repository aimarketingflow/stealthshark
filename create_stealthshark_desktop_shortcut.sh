#!/bin/bash
# Create StealthShark Desktop Shortcut
# Creates a proper macOS desktop shortcut for StealthShark GUI

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_PATH="$HOME/Desktop"
SHORTCUT_NAME="StealthShark"

echo "🦈 Creating StealthShark Desktop Shortcut..."
echo ""

# Create the .app bundle directory structure
APP_PATH="$DESKTOP_PATH/$SHORTCUT_NAME.app"
mkdir -p "$APP_PATH/Contents/MacOS"
mkdir -p "$APP_PATH/Contents/Resources"

# Create Info.plist
cat > "$APP_PATH/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>StealthShark</string>
    <key>CFBundleIdentifier</key>
    <string>com.stealthshark.launcher</string>
    <key>CFBundleName</key>
    <string>StealthShark</string>
    <key>CFBundleDisplayName</key>
    <string>StealthShark Network Monitor</string>
    <key>CFBundleVersion</key>
    <string>2.0</string>
    <key>CFBundleShortVersionString</key>
    <string>2.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Create the executable launcher script
cat > "$APP_PATH/Contents/MacOS/StealthShark" << EOF
#!/bin/bash
# StealthShark Launcher

cd "$SCRIPT_DIR"
exec /opt/homebrew/bin/python3 multi_interface_shark_gui.py
EOF

# Make executable
chmod +x "$APP_PATH/Contents/MacOS/StealthShark"

# Create a simple icon (text-based placeholder)
# You can replace this with a proper .icns file later
echo "Creating app icon placeholder..."

echo ""
echo "✅ Desktop shortcut created successfully!"
echo ""
echo "📍 Location: $APP_PATH"
echo "🦈 Double-click 'StealthShark.app' on your desktop to launch!"
echo ""
