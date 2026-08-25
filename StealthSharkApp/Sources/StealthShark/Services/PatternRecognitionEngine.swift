import Foundation

/// Analyzes network interface statistics to detect traffic patterns and anomalies
final class PatternRecognitionEngine {
    private var baselineRates: [String: BaselineStats] = [:]
    private var lastPatternCheck: Date = .distantPast
    private let checkInterval: TimeInterval = 10 // Check every 10 seconds

    struct BaselineStats {
        var avgBytesRecvRate: Double = 0
        var avgBytesSentRate: Double = 0
        var avgPacketsRecvRate: Double = 0
        var avgPacketsSentRate: Double = 0
        var sampleCount: Int = 0
        var maxBytesRecvRate: Double = 0
        var maxBytesSentRate: Double = 0
    }

    // MARK: - Analysis
    func analyze(interfaces: [NetworkInterface]) -> [TrafficPattern] {
        let now = Date()
        guard now.timeIntervalSince(lastPatternCheck) >= checkInterval else { return [] }
        lastPatternCheck = now

        var detected: [TrafficPattern] = []
        let upInterfaces = interfaces.filter(\.isUp)
        DebugLog.trace("analyze(): \(upInterfaces.count) up interfaces to check", source: "PatternEngine")

        for iface in upInterfaces {
            // Update baseline
            updateBaseline(for: iface)

            // Check for patterns
            if let pattern = checkHighTraffic(iface) {
                detected.append(pattern)
                DebugLog.debug("analyze(): highTraffic triggered on \(iface.name)", source: "PatternEngine")
            }
            if let pattern = checkDataExfiltration(iface) {
                detected.append(pattern)
                DebugLog.debug("analyze(): dataExfiltration triggered on \(iface.name)", source: "PatternEngine")
            }
            if let pattern = checkNewActivity(iface) {
                detected.append(pattern)
                DebugLog.debug("analyze(): newConnection triggered on \(iface.name)", source: "PatternEngine")
            }
        }

        if !detected.isEmpty {
            DebugLog.info("analyze(): detected \(detected.count) pattern(s)", source: "PatternEngine")
        }
        return detected
    }

    // MARK: - Baseline Tracking
    private func updateBaseline(for iface: NetworkInterface) {
        var baseline = baselineRates[iface.name] ?? BaselineStats()

        let n = Double(baseline.sampleCount)
        // Running average
        baseline.avgBytesRecvRate = (baseline.avgBytesRecvRate * n + iface.bytesRecvRate) / (n + 1)
        baseline.avgBytesSentRate = (baseline.avgBytesSentRate * n + iface.bytesSentRate) / (n + 1)
        baseline.avgPacketsRecvRate = (baseline.avgPacketsRecvRate * n + iface.packetsRecvRate) / (n + 1)
        baseline.avgPacketsSentRate = (baseline.avgPacketsSentRate * n + iface.packetsSentRate) / (n + 1)
        baseline.maxBytesRecvRate = max(baseline.maxBytesRecvRate, iface.bytesRecvRate)
        baseline.maxBytesSentRate = max(baseline.maxBytesSentRate, iface.bytesSentRate)
        baseline.sampleCount += 1

        baselineRates[iface.name] = baseline

        if baseline.sampleCount <= 3 {
            DebugLog.trace("updateBaseline(\(iface.name)): sample #\(baseline.sampleCount), avgRx=\(formatBytes(baseline.avgBytesRecvRate))/s, avgTx=\(formatBytes(baseline.avgBytesSentRate))/s", source: "PatternEngine")
        }
    }

    // MARK: - Pattern Checks
    private func checkHighTraffic(_ iface: NetworkInterface) -> TrafficPattern? {
        guard let baseline = baselineRates[iface.name],
              baseline.sampleCount > 10 else { return nil }

        let threshold = max(baseline.avgBytesRecvRate * 5, 1_000_000) // 5x average or 1MB/s
        if iface.bytesRecvRate > threshold || iface.bytesSentRate > threshold {
            let rate = max(iface.bytesRecvRate, iface.bytesSentRate)
            DebugLog.debug("checkHighTraffic(\(iface.name)): rate=\(formatBytes(rate))/s > threshold=\(formatBytes(threshold))/s", source: "PatternEngine")
            return TrafficPattern(
                timestamp: Date(),
                interface: iface.name,
                patternType: .highTraffic,
                description: "Traffic spike: \(formatBytes(rate))/s on \(iface.displayName)",
                severity: rate > threshold * 3 ? .critical : .warning
            )
        }
        return nil
    }

    private func checkDataExfiltration(_ iface: NetworkInterface) -> TrafficPattern? {
        guard let baseline = baselineRates[iface.name],
              baseline.sampleCount > 30 else { return nil }

        // Flag if outbound >> inbound (unusual ratio)
        let sentRecvRatio = iface.bytesSentRate / max(iface.bytesRecvRate, 1)
        if sentRecvRatio > 10 && iface.bytesSentRate > 500_000 { // 10:1 ratio, > 500KB/s out
            DebugLog.debug("checkDataExfiltration(\(iface.name)): ratio=\(String(format: "%.1f", sentRecvRatio)):1, txRate=\(formatBytes(iface.bytesSentRate))/s", source: "PatternEngine")
            return TrafficPattern(
                timestamp: Date(),
                interface: iface.name,
                patternType: .dataExfiltration,
                description: "High outbound ratio (\(String(format: "%.1f", sentRecvRatio)):1) on \(iface.displayName)",
                severity: .warning
            )
        }
        return nil
    }

    private func checkNewActivity(_ iface: NetworkInterface) -> TrafficPattern? {
        guard let baseline = baselineRates[iface.name] else { return nil }

        // Only fire once when an interface transitions from idle to active
        if baseline.sampleCount == 1 && iface.hasActivity {
            DebugLog.debug("checkNewActivity(\(iface.name)): first sample with activity", source: "PatternEngine")
            return TrafficPattern(
                timestamp: Date(),
                interface: iface.name,
                patternType: .newConnection,
                description: "New activity detected on \(iface.displayName)",
                severity: .info
            )
        }
        return nil
    }

    // MARK: - Helpers
    private func formatBytes(_ bytes: Double) -> String {
        if bytes >= 1_000_000_000 { return String(format: "%.1f GB", bytes / 1_000_000_000) }
        if bytes >= 1_000_000 { return String(format: "%.1f MB", bytes / 1_000_000) }
        if bytes >= 1_000 { return String(format: "%.1f KB", bytes / 1_000) }
        return "\(Int(bytes)) B"
    }

    /// Reset baselines (e.g., after major network change)
    func resetBaselines() {
        baselineRates.removeAll()
    }
}
