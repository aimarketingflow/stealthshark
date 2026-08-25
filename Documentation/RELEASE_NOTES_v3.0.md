# StealthShark v3.0 — Native Swift/SwiftUI macOS App

**Release Date:** August 2026
**Platform:** macOS 14+ (Sonoma and later)
**Architecture:** Apple Silicon (arm64) native

---

## What's New

StealthShark has been completely rebuilt from the ground up as a **native Swift/SwiftUI macOS application**, replacing the previous Python/PyQt6/PyInstaller version. The result is a fast, lightweight, and fully native network monitoring tool.

### Why Swift?

| | Python (v2.x) | Swift (v3.0) |
|---|---|---|
| App size | 81 MB (PyInstaller bundle) | ~3.3 MB |
| Startup time | 3-5 seconds | <1 second |
| Memory usage | 150-300 MB (Python runtime) | 30-60 MB |
| UI framework | PyQt6 (cross-platform) | SwiftUI (native macOS) |
| Distribution | Unsigned .app wrapper | Ad-hoc signed .app bundle |
| Build tool | PyInstaller + venv | Swift Package Manager (CLI only) |

### Key Features

- **Multi-interface monitoring** — Real-time stats for all network interfaces (en0, utun*, awdl0, lo0, etc.) with bytes/packets sent/received and live rates
- **tshark packet capture** — Launches tshark processes per-interface with automatic file rotation (hourly or at 100 MB)
- **Pattern recognition** — Detects high traffic spikes, unusual outbound ratios, new interface activity with severity-rated alerts
- **Menu bar integration** — Runs in the macOS menu bar with quick status and start/stop controls; window can be hidden while monitoring continues
- **Session persistence** — Auto-saves state to JSON; restores on relaunch
- **Auto-restart** — Configurable automatic restart by duration (hours + minutes) or capture size (GB) to manage long-running sessions and memory
- **Debug logging panel** — Built-in expandable debug panel with trace/debug/info/warn/error levels, filtering, and copy-to-clipboard
- **Dark theme** — Uses native macOS system appearance

### Architecture

```
StealthSharkApp/
  Package.swift                          # SPM manifest, macOS 14+, no external deps
  Sources/StealthShark/
    StealthSharkApp.swift                # @main App struct, WindowGroup + MenuBarExtra
    Models/
      AppState.swift                     # @MainActor ObservableObject, central state
      DataModels.swift                   # NetworkInterface, CaptureStats, PatternAlert
      DebugLog.swift                     # Thread-safe singleton logger (1000-entry FIFO)
    Services/
      NetworkMonitorService.swift        # getifaddrs + netstat polling, rate calculation
      CaptureEngine.swift                # tshark Process management, file rotation
      PatternRecognitionEngine.swift     # Traffic anomaly detection
      SessionManager.swift               # Preferences + session save/restore (JSON)
    Views/
      ContentView.swift                  # NavigationSplitView sidebar
      MonitorDashboardView.swift         # Live stats dashboard
      InterfacesView.swift               # Interface list with details
      CaptureView.swift                  # Capture start/stop, live file list
      PatternsView.swift                 # Pattern alerts table
      SettingsView.swift                 # All preferences
      MenuBarView.swift                  # Menu bar extra content
      DebugPanelView.swift               # Expandable bottom debug log panel
  build_app.sh                           # Packages binary into .app bundle
```

**Total source:** ~2,700 lines of Swift (no external dependencies)

### Build & Install

```bash
cd StealthSharkApp
swift build -c release          # Compile (~5s on M-series)
bash build_app.sh               # Package .app bundle
cp -R dist/StealthShark.app /Applications/
open /Applications/StealthShark.app
```

**Requirements:**
- macOS 14+ (Sonoma)
- Swift toolchain (included with Xcode or Xcode Command Line Tools)
- tshark at `/opt/homebrew/bin/tshark` (install via `brew install wireshark`)

### Auto-Restart Feature

StealthShark can automatically stop, save state, and restart monitoring to manage memory and rotate capture sessions:

- **By duration:** Default 4 hours (configurable 0-24 hours + 0-59 minutes)
- **By capture size:** Default 2 GB (configurable 0-500 GB)
- Whichever threshold is hit first triggers the restart
- Toggle on/off independently in Settings > Auto-Restart

### Data Storage

All data is stored in `~/Library/Application Support/StealthShark/`:
- `pcap_captures/` — .pcapng capture files
- `sessions/` — Session state and preferences JSON
- `logs/` — Application logs

---

## Migration from Python Version

The Python version (`multi_interface_shark_gui.py`) remains untouched and can still be run independently. The Swift version is a parallel rebuild — both read/write the same capture directory structure, so existing pcap files are accessible from either version.

No data migration is needed. Simply install the new `.app` and start monitoring.
