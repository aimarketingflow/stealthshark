# Spec 01: Rebuild StealthShark as Native Swift/SwiftUI macOS App

## Objective

Rebuild the StealthShark network monitor from a Python/PyQt6/PyInstaller app into a **native Swift/SwiftUI macOS application**. The result should be a lightweight, self-contained `.app` bundle that installs to `/Applications/StealthShark.app`.

## Background

StealthShark is currently a Python GUI app (`multi_interface_shark_gui.py`, ~75KB) using PyQt6, bundled via PyInstaller into an 81MB .app. The Python source lives at:
- `multi_interface_shark_gui.py` (repo root)
- `persistent_wireshark_monitor.py` (repo root)

A Swift rewrite already exists as a skeleton at:
- `StealthSharkApp/` (repo root)

This skeleton compiles and builds but needs to be verified as feature-complete, tested, and installed.

## Requirements

### Core Features (must match Python version)

1. **Multi-interface network monitoring** — Discover all system network interfaces (en0, lo0, utun*, awdl0, etc.) using `getifaddrs` and display real-time stats (bytes/packets sent/recv, rates)
2. **tshark packet capture** — Launch `tshark` via `Process()` on active interfaces, manage rotation (hourly / 100MB), store `.pcapng` files in `~/Library/Application Support/StealthShark/pcap_captures/`
3. **Pattern recognition** — Detect high traffic spikes, unusual outbound ratios, new interface activity. Alert with severity levels.
4. **Session persistence** — Save/restore state to JSON in Application Support. Auto-save periodically.
5. **Menu bar presence** — App runs in menu bar with quick status + start/stop controls. Window can be hidden while monitoring continues.
6. **Dark theme / native macOS look** — Use SwiftUI's system appearance, NavigationSplitView sidebar.
7. **Settings** — Configurable rotation interval, max disk usage, auto-cleanup, auto-start capture.

### Architecture

- **SwiftUI** with `@main` App struct
- **NavigationSplitView** sidebar with tabs: Monitor, Interfaces, Capture, Patterns, Settings
- **Services layer**: `NetworkMonitorService`, `CaptureEngine`, `PatternRecognitionEngine`, `SessionManager`
- **Models**: `AppState` (ObservableObject), data models in `DataModels.swift`
- **Menu bar**: `MenuBarExtra` with status and controls
- **Minimum deployment**: macOS 14+
- **Package.swift** based (no Xcode project file required)

### Build & Packaging

- `swift build -c release` produces the binary
- `build_app.sh` packages into `.app` bundle with:
  - `Info.plist` (bundle ID: `com.aimf.stealthshark`, version 3.0.0)
  - App icon from `stealth-shark-logo.icns`
  - Ad-hoc codesigning
- Final app installed to `/Applications/StealthShark.app`
- Desktop symlink at `~/Desktop/StealthShark.app`

### What Already Exists

The Swift skeleton is in place at `StealthSharkApp/` with these files:
- `Package.swift`
- `Sources/StealthShark/StealthSharkApp.swift`
- `Sources/StealthShark/Models/AppState.swift`
- `Sources/StealthShark/Models/DataModels.swift`
- `Sources/StealthShark/Services/NetworkMonitorService.swift`
- `Sources/StealthShark/Services/CaptureEngine.swift`
- `Sources/StealthShark/Services/PatternRecognitionEngine.swift`
- `Sources/StealthShark/Services/SessionManager.swift`
- `Sources/StealthShark/Views/ContentView.swift`
- `Sources/StealthShark/Views/MonitorDashboardView.swift`
- `Sources/StealthShark/Views/InterfacesView.swift`
- `Sources/StealthShark/Views/CaptureView.swift`
- `Sources/StealthShark/Views/PatternsView.swift`
- `Sources/StealthShark/Views/SettingsView.swift`
- `Sources/StealthShark/Views/MenuBarView.swift`
- `build_app.sh`

The code compiles and builds (`swift build -c release` succeeds, ~3MB .app bundle).

## DA Responsibilities

1. **Verify the existing build** — Run `swift build -c release` and `bash build_app.sh`, confirm success
2. **Launch test** — Run the .app, confirm the window appears with all tabs functional
3. **Fix any runtime issues** — Ensure interface discovery works, tshark capture starts/stops, session saves
4. **Install** — Place final .app in `/Applications/`, verify launch from there
5. **Report** — Document what works, any issues found, evidence of successful build + launch

## Verification Criteria

- [ ] `swift build -c release` exits 0
- [ ] `build_app.sh` produces a valid .app bundle
- [ ] App launches without crash
- [ ] Sidebar navigation works (all 5 tabs)
- [ ] Interface discovery shows system interfaces
- [ ] Start/Stop monitoring button works
- [ ] Menu bar icon appears
- [ ] Settings page renders
- [ ] App quits cleanly

## Critical Implementation Constraints

- Do NOT use any external Swift dependencies (no SPM packages) — stdlib only
- Do NOT require Xcode.app to build (swift CLI + Package.swift only)
- tshark must be at `/opt/homebrew/bin/tshark` (already installed via Homebrew)
- All data stored in `~/Library/Application Support/StealthShark/`
- The Python version should remain untouched (this is a parallel native rebuild)
