import SwiftUI

struct CaptureView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingCleanupAlert = false

    var body: some View {
        VStack(spacing: 16) {
            // Capture Status Header
            captureStatusHeader

            // Capture Files Table
            captureFilesSection

            Spacer()
        }
        .padding()
        .navigationTitle("Packet Capture")
        .alert("Cleanup Captures", isPresented: $showingCleanupAlert) {
            Button("Cancel", role: .cancel) {}
            Button("Delete Old Captures", role: .destructive) {
                appState.captureEngine.cleanupOldCaptures()
            }
        } message: {
            Text("This will delete capture files older than 7 days. This cannot be undone.")
        }
    }

    // MARK: - Status Header
    private var captureStatusHeader: some View {
        HStack(spacing: 20) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Circle()
                        .fill(appState.isCapturing ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(appState.isCapturing ? "Capturing" : "Idle")
                        .font(.headline)
                }

                if appState.captureEngine.isTSharkAvailable {
                    Text("tshark available")
                        .font(.caption)
                        .foregroundStyle(.green)
                } else {
                    Text("tshark not found — install Wireshark")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            Divider().frame(height: 40)

            VStack(alignment: .leading) {
                Text("Active Captures")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("\(appState.captureStats.activeCaptureCount)")
                    .font(.title2.bold())
            }

            Divider().frame(height: 40)

            VStack(alignment: .leading) {
                Text("Total Data")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(formatBytes(appState.captureStats.totalBytes))
                    .font(.title2.bold())
            }

            Divider().frame(height: 40)

            VStack(alignment: .leading) {
                Text("Duration")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(appState.captureStats.formattedElapsed)
                    .font(.title2.bold().monospaced())
            }

            Spacer()

            VStack(spacing: 8) {
                if !appState.isMonitoring {
                    Text("Capture is controlled via\nStart/Stop Monitoring")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                Button {
                    showingCleanupAlert = true
                } label: {
                    Label("Cleanup", systemImage: "trash")
                }
                .controlSize(.small)
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Capture Files
    private var captureFilesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Capture Files")
                .font(.headline)

            if appState.captureStats.captureFiles.isEmpty {
                ContentUnavailableView(
                    "No Captures",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text("Start Monitoring to begin capturing network traffic")
                )
                .frame(minHeight: 200)
            } else {
                Table(appState.captureStats.captureFiles) {
                    TableColumn("File") { file in
                        Text(file.filename)
                            .font(.system(.caption, design: .monospaced))
                    }
                    TableColumn("Interface") { file in
                        Text(file.interface)
                            .font(.caption)
                    }
                    .width(80)
                    TableColumn("Started") { file in
                        Text(file.startTime, style: .time)
                            .font(.caption)
                    }
                    .width(80)
                    TableColumn("Size") { file in
                        Text(formatBytes(file.size))
                            .font(.system(.caption, design: .monospaced))
                    }
                    .width(80)
                }
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Helpers
    private func formatBytes(_ bytes: UInt64) -> String {
        if bytes >= 1_000_000_000 { return String(format: "%.1f GB", Double(bytes) / 1_000_000_000) }
        if bytes >= 1_000_000 { return String(format: "%.1f MB", Double(bytes) / 1_000_000) }
        if bytes >= 1_000 { return String(format: "%.1f KB", Double(bytes) / 1_000) }
        return "\(bytes) B"
    }
}
