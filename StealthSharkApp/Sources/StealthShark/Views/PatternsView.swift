import SwiftUI

struct PatternsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedSeverity: TrafficPattern.Severity?

    var filteredPatterns: [TrafficPattern] {
        if let severity = selectedSeverity {
            return appState.patterns.filter { $0.severity == severity }
        }
        return appState.patterns
    }

    var body: some View {
        VStack(spacing: 16) {
            // Summary Bar
            summaryBar

            // Filters
            filterBar

            // Pattern List
            if filteredPatterns.isEmpty {
                ContentUnavailableView(
                    "No Patterns Detected",
                    systemImage: "brain",
                    description: Text("The pattern engine analyzes traffic in real-time.\nPatterns will appear here when anomalies are detected.")
                )
            } else {
                List(filteredPatterns) { pattern in
                    PatternRow(pattern: pattern)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .padding()
        .navigationTitle("Pattern Recognition")
    }

    // MARK: - Summary
    private var summaryBar: some View {
        HStack(spacing: 20) {
            SeverityBadge(
                severity: .info,
                count: appState.patterns.filter { $0.severity == .info }.count
            )
            SeverityBadge(
                severity: .warning,
                count: appState.patterns.filter { $0.severity == .warning }.count
            )
            SeverityBadge(
                severity: .critical,
                count: appState.patterns.filter { $0.severity == .critical }.count
            )
            Spacer()

            Button("Clear All") {
                appState.patterns.removeAll()
            }
            .controlSize(.small)
            .disabled(appState.patterns.isEmpty)

            Button {
                appState.patternEngine.resetBaselines()
            } label: {
                Label("Reset Baselines", systemImage: "arrow.counterclockwise")
            }
            .controlSize(.small)
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Filters
    private var filterBar: some View {
        HStack {
            Text("Filter:")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button("All") { selectedSeverity = nil }
                .buttonStyle(.bordered)
                .tint(selectedSeverity == nil ? .blue : .gray)
                .controlSize(.small)

            ForEach(TrafficPattern.Severity.allCases, id: \.rawValue) { severity in
                Button(severity.rawValue) { selectedSeverity = severity }
                    .buttonStyle(.bordered)
                    .tint(selectedSeverity == severity ? Color(severity.color) : .gray)
                    .controlSize(.small)
            }

            Spacer()
        }
    }
}

// MARK: - Pattern Row
struct PatternRow: View {
    let pattern: TrafficPattern

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: pattern.severity.icon)
                .foregroundStyle(Color(pattern.severity.color))
                .font(.title3)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(pattern.patternType.rawValue)
                        .font(.callout.bold())
                    Text("on \(pattern.interface)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(pattern.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Spacer()

            Text(pattern.timestamp, style: .time)
                .font(.caption.monospaced())
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Severity Badge
struct SeverityBadge: View {
    let severity: TrafficPattern.Severity
    let count: Int

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: severity.icon)
                .foregroundStyle(Color(severity.color))
            Text("\(count)")
                .font(.headline)
            Text(severity.rawValue)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Color(severity.color).opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }
}
