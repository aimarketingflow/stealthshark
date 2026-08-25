import SwiftUI

struct MonitorDashboardView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Status Header
                statusHeader

                // Stats Cards
                statsGrid

                // Activity Log
                activitySection
            }
            .padding()
        }
        .navigationTitle("Monitor")
    }

    // MARK: - Status Header
    private var statusHeader: some View {
        HStack {
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 32))
                .foregroundStyle(appState.isMonitoring ? .green : .gray)

            VStack(alignment: .leading, spacing: 4) {
                Text(appState.statusMessage)
                    .font(.headline)
                if appState.isMonitoring {
                    Text("Elapsed: \(appState.captureStats.formattedElapsed)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button {
                DebugLog.info("[UI] Monitor tab Start/Stop clicked, isMonitoring=\(appState.isMonitoring)", source: "UI")
                if appState.isMonitoring {
                    appState.stopMonitoring()
                } else {
                    appState.startMonitoring()
                }
            } label: {
                Label(
                    appState.isMonitoring ? "Stop" : "Start Monitoring",
                    systemImage: appState.isMonitoring ? "stop.circle.fill" : "play.circle.fill"
                )
            }
            .buttonStyle(.borderedProminent)
            .tint(appState.isMonitoring ? .red : .green)
            .controlSize(.large)
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Stats Grid
    private var statsGrid: some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible())
        ], spacing: 12) {
            StatCard(
                title: "Interfaces",
                value: "\(appState.interfaces.count)",
                subtitle: "\(appState.interfaces.filter(\.isUp).count) up",
                icon: "network",
                color: .blue
            )
            StatCard(
                title: "Active",
                value: "\(appState.interfaces.filter(\.hasActivity).count)",
                subtitle: "with traffic",
                icon: "bolt.circle",
                color: .green
            )
            StatCard(
                title: "Captures",
                value: "\(appState.captureStats.activeCaptureCount)",
                subtitle: "running",
                icon: "internaldrive",
                color: .orange
            )
            StatCard(
                title: "Patterns",
                value: "\(appState.patterns.count)",
                subtitle: "detected",
                icon: "brain",
                color: .purple
            )
        }
    }

    // MARK: - Activity Section
    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Activity Log")
                    .font(.headline)
                Spacer()
                Text("\(appState.activityLog.count) entries")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if appState.activityLog.isEmpty {
                ContentUnavailableView(
                    "No Activity",
                    systemImage: "tray",
                    description: Text("Start monitoring to see activity")
                )
                .frame(height: 150)
            } else {
                LazyVStack(spacing: 4) {
                    ForEach(appState.activityLog.prefix(50)) { entry in
                        ActivityRow(entry: entry)
                    }
                }
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Stat Card
struct StatCard: View {
    let title: String
    let value: String
    let subtitle: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(color)

            Text(value)
                .font(.system(size: 28, weight: .bold, design: .rounded))

            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)

            Text(subtitle)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Activity Row
struct ActivityRow: View {
    let entry: ActivityEntry

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: entry.type.icon)
                .foregroundStyle(Color(entry.type.color))
                .frame(width: 20)

            Text(entry.formattedTime)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)

            Text(entry.message)
                .font(.callout)
                .lineLimit(1)

            Spacer()
        }
        .padding(.vertical, 2)
    }
}
