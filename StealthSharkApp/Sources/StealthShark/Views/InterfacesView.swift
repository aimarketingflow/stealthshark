import SwiftUI

struct InterfacesView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""
    @State private var showOnlyActive = false

    var filteredInterfaces: [NetworkInterface] {
        var list = appState.interfaces
        if showOnlyActive {
            list = list.filter { $0.isUp }
        }
        if !searchText.isEmpty {
            list = list.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.displayName.localizedCaseInsensitiveContains(searchText) ||
                $0.ipAddresses.joined().contains(searchText)
            }
        }
        return list
    }

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Toggle("Active Only", isOn: $showOnlyActive)
                    .toggleStyle(.switch)
                    .controlSize(.small)

                Spacer()

                Button {
                    DebugLog.info("[UI] Interfaces tab 'Refresh' clicked", source: "UI")
                    let monitor = appState.networkMonitor
                    Task.detached {
                        autoreleasepool {
                            monitor.discoverInterfaces()
                        }
                        let discovered = monitor.interfaces
                        await MainActor.run {
                            appState.interfaces = discovered
                        }
                    }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            // Interface Table
            Table(filteredInterfaces) {
                TableColumn("Status") { iface in
                    HStack(spacing: 4) {
                        Image(systemName: iface.statusIcon)
                            .foregroundStyle(Color(iface.statusColor))
                            .font(.caption)
                    }
                }
                .width(min: 40, ideal: 50, max: 60)

                TableColumn("Interface") { iface in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(iface.displayName)
                            .font(.callout.bold())
                        if !iface.ipAddresses.isEmpty {
                            Text(iface.ipAddresses.joined(separator: ", "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .width(min: 150, ideal: 200)

                TableColumn("RX Rate") { iface in
                    Text(formatRate(iface.bytesRecvRate))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(iface.bytesRecvRate > 0 ? .primary : .secondary)
                }
                .width(min: 80, ideal: 100)

                TableColumn("TX Rate") { iface in
                    Text(formatRate(iface.bytesSentRate))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(iface.bytesSentRate > 0 ? .primary : .secondary)
                }
                .width(min: 80, ideal: 100)

                TableColumn("Packets RX") { iface in
                    Text(formatCount(iface.packetsRecv))
                        .font(.system(.caption, design: .monospaced))
                }
                .width(min: 80, ideal: 100)

                TableColumn("Packets TX") { iface in
                    Text(formatCount(iface.packetsSent))
                        .font(.system(.caption, design: .monospaced))
                }
                .width(min: 80, ideal: 100)

                TableColumn("Total RX") { iface in
                    Text(formatBytes(iface.bytesRecv))
                        .font(.system(.caption, design: .monospaced))
                }
                .width(min: 80, ideal: 100)

                TableColumn("Total TX") { iface in
                    Text(formatBytes(iface.bytesSent))
                        .font(.system(.caption, design: .monospaced))
                }
                .width(min: 80, ideal: 100)
            }
        }
        .searchable(text: $searchText, prompt: "Filter interfaces...")
        .navigationTitle("Network Interfaces")
    }

    // MARK: - Formatters
    private func formatRate(_ bytesPerSec: Double) -> String {
        if bytesPerSec >= 1_000_000_000 { return String(format: "%.1f GB/s", bytesPerSec / 1_000_000_000) }
        if bytesPerSec >= 1_000_000 { return String(format: "%.1f MB/s", bytesPerSec / 1_000_000) }
        if bytesPerSec >= 1_000 { return String(format: "%.1f KB/s", bytesPerSec / 1_000) }
        if bytesPerSec > 0 { return String(format: "%.0f B/s", bytesPerSec) }
        return "—"
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        if bytes >= 1_000_000_000 { return String(format: "%.1f GB", Double(bytes) / 1_000_000_000) }
        if bytes >= 1_000_000 { return String(format: "%.1f MB", Double(bytes) / 1_000_000) }
        if bytes >= 1_000 { return String(format: "%.1f KB", Double(bytes) / 1_000) }
        return "\(bytes) B"
    }

    private func formatCount(_ count: UInt64) -> String {
        if count >= 1_000_000 { return String(format: "%.1fM", Double(count) / 1_000_000) }
        if count >= 1_000 { return String(format: "%.1fK", Double(count) / 1_000) }
        return "\(count)"
    }
}
