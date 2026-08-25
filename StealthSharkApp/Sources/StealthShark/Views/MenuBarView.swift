import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Status
            HStack {
                Circle()
                    .fill(appState.isMonitoring ? Color.green : Color.gray)
                    .frame(width: 8, height: 8)
                Text(appState.isMonitoring ? "Monitoring" : "Stopped")
            }

            if appState.isMonitoring {
                Text("\(appState.interfaces.filter(\.isUp).count) interfaces | \(appState.captureStats.formattedElapsed)")
                    .font(.caption)
            }

            Divider()

            Button(appState.isMonitoring ? "Stop Monitoring" : "Start Monitoring") {
                DebugLog.info("[UI] MenuBar Start/Stop clicked, isMonitoring=\(appState.isMonitoring)", source: "UI")
                if appState.isMonitoring {
                    appState.stopMonitoring()
                } else {
                    appState.startMonitoring()
                }
            }
            .keyboardShortcut("m")

            Divider()

            Button("Show Window") {
                DebugLog.debug("[UI] MenuBar 'Show Window' clicked", source: "UI")
                NSApp.activate(ignoringOtherApps: true)
                if let window = NSApp.windows.first {
                    window.makeKeyAndOrderFront(nil)
                }
            }

            Divider()

            Button("Quit StealthShark") {
                DebugLog.info("[UI] MenuBar 'Quit' clicked", source: "UI")
                appState.stopMonitoring()
                appState.saveSessionState()
                NSApp.terminate(nil)
            }
            .keyboardShortcut("q")
        }
    }
}
