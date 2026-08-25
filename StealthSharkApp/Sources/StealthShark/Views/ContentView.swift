import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationSplitView {
            SidebarView()
        } detail: {
            VStack(spacing: 0) {
                detailView
                DebugPanelView()
            }
        }
        .navigationSplitViewStyle(.balanced)
    }

    @ViewBuilder
    private var detailView: some View {
        switch appState.selectedTab {
        case .monitor:
            MonitorDashboardView()
        case .interfaces:
            InterfacesView()
        case .capture:
            CaptureView()
        case .patterns:
            PatternsView()
        case .settings:
            SettingsView()
        }
    }
}

// MARK: - Sidebar
struct SidebarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        List(selection: $appState.selectedTab) {
            Section("Navigation") {
                ForEach(AppTab.allCases) { tab in
                    Label(tab.rawValue, systemImage: tab.icon)
                        .tag(tab)
                }
            }

            Section("Status") {
                HStack {
                    Circle()
                        .fill(appState.isMonitoring ? Color.green : Color.gray)
                        .frame(width: 8, height: 8)
                    Text(appState.isMonitoring ? "Monitoring" : "Stopped")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if appState.isMonitoring {
                    Text("\(appState.interfaces.filter(\.isUp).count) interfaces active")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            Section("Quick Actions") {
                Button {
                    DebugLog.info("[UI] Sidebar Start/Stop button clicked, isMonitoring=\(appState.isMonitoring)", source: "UI")
                    if appState.isMonitoring {
                        appState.stopMonitoring()
                    } else {
                        appState.startMonitoring()
                    }
                } label: {
                    Label(
                        appState.isMonitoring ? "Stop" : "Start",
                        systemImage: appState.isMonitoring ? "stop.fill" : "play.fill"
                    )
                }
                .buttonStyle(.borderedProminent)
                .tint(appState.isMonitoring ? .red : .green)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("StealthShark")
        .onChange(of: appState.selectedTab) { _, newTab in
            DebugLog.debug("[UI] Tab switched to: \(newTab.rawValue)", source: "UI")
        }
    }
}
