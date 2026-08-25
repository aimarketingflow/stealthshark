import SwiftUI

@main
struct StealthSharkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var appState = AppState.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .frame(minWidth: 900, minHeight: 600)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1100, height: 750)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Monitor") {
                Button("Start Monitoring") {
                    appState.startMonitoring()
                }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(appState.isMonitoring)

                Button("Stop Monitoring") {
                    appState.stopMonitoring()
                }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(!appState.isMonitoring)

                Divider()

                Button("Refresh Interfaces") {
                    appState.networkMonitor.discoverInterfaces()
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
            }
        }

        MenuBarExtra("StealthShark", systemImage: "network.badge.shield.half.filled") {
            MenuBarView()
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DebugLog.info("=== StealthShark launching ===", source: "AppState")
        DebugLog.info("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)", source: "AppState")
        DebugLog.info("App version: 3.0.0 (Swift/SwiftUI Native)", source: "AppState")
        // Setup app data directories
        AppState.shared.setupDirectories()
        DebugLog.info("=== StealthShark launch complete ===", source: "AppState")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        DebugLog.debug("applicationShouldTerminateAfterLastWindowClosed → false (keep in menu bar)", source: "AppState")
        return false // Keep running in menu bar
    }

    func applicationWillTerminate(_ notification: Notification) {
        DebugLog.info("=== StealthShark terminating ===", source: "AppState")
        AppState.shared.stopMonitoring()
        AppState.shared.stopCapture()
        AppState.shared.saveSessionState()
        DebugLog.info("=== StealthShark terminated ===", source: "AppState")
    }
}
