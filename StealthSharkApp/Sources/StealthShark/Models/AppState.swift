import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    static let shared = AppState()

    // MARK: - Published State
    @Published var isMonitoring = false
    @Published var isCapturing = false
    @Published var statusMessage = "Ready"
    @Published var interfaces: [NetworkInterface] = []
    @Published var captureStats = CaptureStats()
    @Published var activityLog: [ActivityEntry] = []
    @Published var patterns: [TrafficPattern] = []
    @Published var selectedTab: AppTab = .monitor

    // MARK: - Services
    // nonisolated: these are immutable let constants, safe to access from
    // the detached monitoring task without hopping to the MainActor.
    nonisolated let networkMonitor = NetworkMonitorService()
    nonisolated let captureEngine = CaptureEngine()
    nonisolated let patternEngine = PatternRecognitionEngine()
    nonisolated let sessionManager = SessionManager()

    // MARK: - Private
    private var monitoringTask: Task<Void, Never>?
    private var captureStatsTask: Task<Void, Never>?

    private init() {
        restoreSession()
    }

    // MARK: - Directories
    func setupDirectories() {
        DebugLog.info("setupDirectories() called", source: "AppState")
        let dirs = [
            appSupportDir,
            appSupportDir.appendingPathComponent("pcap_captures"),
            appSupportDir.appendingPathComponent("logs"),
            appSupportDir.appendingPathComponent("sessions")
        ]
        for dir in dirs {
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                DebugLog.debug("Created/verified dir: \(dir.path)", source: "AppState")
            } catch {
                DebugLog.error("Failed to create dir \(dir.path): \(error)", source: "AppState")
            }
        }
        DebugLog.info("App Support root: \(appSupportDir.path)", source: "AppState")
    }

    var appSupportDir: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport.appendingPathComponent("StealthShark")
    }

    // MARK: - Monitoring Control
    func startMonitoring() {
        guard !isMonitoring else {
            DebugLog.warn("startMonitoring() called but already monitoring", source: "AppState")
            return
        }
        DebugLog.info("startMonitoring() — entering", source: "AppState")
        isMonitoring = true
        statusMessage = "Starting multi-interface monitoring..."
        log("Monitoring started", type: .info)

        // Task.detached runs OFF the MainActor so the heavy netstat/tshark
        // work does not block the UI. We hop to MainActor.run for UI updates.
        monitoringTask = Task.detached { [weak self] in
            guard let self = self else {
                DebugLog.error("monitoringTask: self is nil", source: "AppState")
                return
            }

            DebugLog.debug("monitoringTask: starting interface discovery", source: "AppState")

            // Initial discovery (runs on background thread)
            self.networkMonitor.discoverInterfaces()
            let discovered = self.networkMonitor.interfaces
            DebugLog.info("monitoringTask: discovered \(discovered.count) interfaces, \(discovered.filter(\.isUp).count) up", source: "AppState")
            for iface in discovered {
                DebugLog.trace("  iface: \(iface.name) up=\(iface.isUp) ips=\(iface.ipAddresses) rx=\(iface.bytesRecv) tx=\(iface.bytesSent)", source: "AppState")
            }

            await MainActor.run {
                self.interfaces = discovered
                self.statusMessage = "Monitoring \(discovered.filter(\.isUp).count) active interfaces"
                self.log("Discovered \(discovered.count) interfaces", type: .info)
                let upInterfaces = discovered.filter(\.isUp)
                DebugLog.debug("monitoringTask: starting capture on \(upInterfaces.count) up interfaces", source: "AppState")
                self.captureEngine.startCapture(interfaces: upInterfaces)
                self.isCapturing = true
                // Immediate stats refresh so Capture tab updates without waiting for first poll tick
                self.captureStats = self.captureEngine.currentStats
                DebugLog.trace("monitoringTask: initial captureStats active=\(self.captureStats.activeCaptureCount)", source: "AppState")
            }

            DebugLog.debug("monitoringTask: entering polling loop", source: "AppState")

            // Stats polling loop — all heavy work on background thread
            var tickCount = 0
            while !Task.isCancelled {
                let stillMonitoring = await MainActor.run { self.isMonitoring }
                if !stillMonitoring {
                    DebugLog.debug("monitoringTask: isMonitoring=false, exiting loop", source: "AppState")
                    break
                }

                // autoreleasepool prevents Process/NSData accumulation
                let stats = autoreleasepool {
                    self.networkMonitor.discoverInterfaces()
                    return self.networkMonitor.interfaces
                }

                // Refresh disk-based file stats so Capture tab totalBytes is current
                self.captureEngine.refreshFileStats()
                let captureStats = self.captureEngine.currentStats
                let newPatterns = self.patternEngine.analyze(interfaces: stats)

                tickCount += 1
                DebugLog.trace("monitoringTask: tick #\(tickCount) — \(stats.count) ifaces, \(newPatterns.count) new patterns, \(captureStats.activeCaptureCount) active captures, \(captureStats.totalBytes) total bytes", source: "AppState")

                await MainActor.run {
                    self.interfaces = stats
                    self.captureStats = captureStats
                    if !newPatterns.isEmpty {
                        self.patterns.append(contentsOf: newPatterns)
                        // Cap patterns to prevent unbounded memory growth
                        if self.patterns.count > 200 {
                            self.patterns.removeFirst(self.patterns.count - 200)
                        }
                        for p in newPatterns {
                            DebugLog.info("Pattern detected: [\(p.severity.rawValue)] \(p.patternType.rawValue) on \(p.interface) — \(p.description)", source: "AppState")
                        }
                    }
                }

                // Auto-restart check every 10 seconds (every 10 ticks at 1s interval)
                if tickCount % 10 == 0 {
                    let restartReason = self.checkAutoRestartThresholds(captureStats: captureStats)
                    if let reason = restartReason {
                        DebugLog.info("monitoringTask: auto-restart threshold reached: \(reason)", source: "AppState")
                        await MainActor.run {
                            self.scheduleAutoRestart(reason: reason)
                        }
                        break
                    }
                }

                try? await Task.sleep(nanoseconds: 1_000_000_000) // 1 second interval (more responsive UI)
            }

            DebugLog.info("monitoringTask: loop ended after \(tickCount) ticks", source: "AppState")
        }
    }

    // MARK: - Auto-Restart Thresholds

    /// Returns a non-nil reason string if auto-restart should be triggered.
    /// nonisolated: called from the detached monitoring task; only reads prefs from the nonisolated SessionManager.
    nonisolated private func checkAutoRestartThresholds(captureStats: CaptureStats) -> String? {
        let prefs = self.sessionManager.loadPreferences()

        let isDurationEnabled = self.sessionManager.isAutoRestartDurationEnabled(prefs: prefs)
        if isDurationEnabled {
            let elapsed = captureStats.elapsedTime
            let threshold = self.sessionManager.autoRestartDurationSeconds(prefs: prefs)
            if elapsed >= threshold {
                let h = prefs.autoRestartHours
                let m = prefs.autoRestartMinutes
                return "elapsed time \(Int(elapsed/60))m reached \(h)h \(m)m limit"
            }
        }

        if prefs.autoRestartCaptureGB > 0 {
            let thresholdBytes = UInt64(prefs.autoRestartCaptureGB) * 1_000_000_000
            if captureStats.totalBytes >= thresholdBytes {
                return "capture size \(captureStats.totalBytes) bytes reached \(prefs.autoRestartCaptureGB) GB limit"
            }
        }

        return nil
    }

    /// Stops monitoring, saves state, and restarts after a short delay.
    private func scheduleAutoRestart(reason: String) {
        guard isMonitoring else {
            DebugLog.debug("scheduleAutoRestart: not monitoring, skipping", source: "AppState")
            return
        }
        DebugLog.info("scheduleAutoRestart: \(reason)", source: "AppState")
        log("Auto-restart scheduled: \(reason)", type: .info)
        stopMonitoring()

        Task.detached { [weak self] in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard let appState = self else { return }
            await MainActor.run {
                guard !appState.isMonitoring else { return }
                DebugLog.info("scheduleAutoRestart: restarting monitoring now", source: "AppState")
                appState.log("Auto-restarting monitoring", type: .info)
                appState.startMonitoring()
            }
        }
    }

    func stopMonitoring() {
        guard isMonitoring else {
            DebugLog.warn("stopMonitoring() called but not monitoring", source: "AppState")
            return
        }
        DebugLog.info("stopMonitoring() — entering", source: "AppState")
        monitoringTask?.cancel()
        monitoringTask = nil
        DebugLog.debug("stopMonitoring(): monitoringTask cancelled", source: "AppState")
        captureEngine.stopCapture()
        isMonitoring = false
        isCapturing = false
        stopCaptureStatsPolling()
        statusMessage = "Monitoring stopped"
        log("Monitoring stopped", type: .info)
        saveSessionState()
        DebugLog.info("stopMonitoring() — done", source: "AppState")
    }

    // MARK: - Capture Control (independent of monitoring)
    func startCapture() {
        guard !isCapturing else {
            DebugLog.warn("startCapture() called but already capturing", source: "AppState")
            return
        }
        guard captureEngine.isTSharkAvailable else {
            statusMessage = "tshark not found — install Wireshark"
            DebugLog.error("startCapture(): tshark not found at any expected path", source: "AppState")
            log("Capture failed: tshark not found", type: .error)
            return
        }

        DebugLog.info("startCapture() — tshark available, checking interfaces", source: "AppState")
        statusMessage = "Discovering interfaces..."

        // Run discovery on background thread to avoid blocking UI
        Task.detached { [weak self] in
            guard let self = self else { return }

            let interfacesToCapture: [NetworkInterface]
            let needsDiscovery: Bool = await MainActor.run {
                self.interfaces.filter(\.isUp).isEmpty
            }

            if needsDiscovery {
                DebugLog.debug("startCapture(): no up interfaces in state, discovering on background...", source: "AppState")
                autoreleasepool {
                    self.networkMonitor.discoverInterfaces()
                }
                let discovered = self.networkMonitor.interfaces
                interfacesToCapture = discovered.filter(\.isUp)
                DebugLog.info("startCapture(): discovery found \(discovered.count) total, \(interfacesToCapture.count) up", source: "AppState")
            } else {
                let existing = await MainActor.run { self.interfaces }
                interfacesToCapture = existing.filter(\.isUp)
                DebugLog.debug("startCapture(): using existing \(interfacesToCapture.count) up interfaces", source: "AppState")
            }

            await MainActor.run {
                guard !interfacesToCapture.isEmpty else {
                    self.statusMessage = "No active interfaces to capture on"
                    DebugLog.warn("startCapture(): no active interfaces to capture on", source: "AppState")
                    self.log("Capture failed: no active interfaces", type: .warning)
                    return
                }

                self.interfaces = self.networkMonitor.interfaces

                for iface in interfacesToCapture {
                    DebugLog.debug("startCapture(): will capture on \(iface.name) (\(iface.displayName))", source: "AppState")
                }

                self.captureEngine.startCapture(interfaces: interfacesToCapture)
                self.isCapturing = true
                self.statusMessage = "Capturing on \(interfacesToCapture.count) interface(s)"
                self.log("Capture started on \(interfacesToCapture.count) interface(s)", type: .capture)
                DebugLog.info("startCapture() — capture started on \(interfacesToCapture.count) interface(s)", source: "AppState")
                self.startCaptureStatsPolling()
            }
        }
    }

    func stopCapture() {
        guard isCapturing else {
            DebugLog.warn("stopCapture() called but not capturing", source: "AppState")
            return
        }
        DebugLog.info("stopCapture() — entering", source: "AppState")
        captureEngine.stopCapture()
        isCapturing = false
        stopCaptureStatsPolling()
        statusMessage = "Capture stopped"
        log("Capture stopped", type: .capture)
        DebugLog.info("stopCapture() — done", source: "AppState")
        saveSessionState()
    }

    // MARK: - Capture Stats Polling
    // When capturing independently of monitoring, we still need to refresh
    // capture file stats so the Capture tab shows live data.
    private func startCaptureStatsPolling() {
        DebugLog.debug("startCaptureStatsPolling() — starting", source: "AppState")
        captureStatsTask = Task.detached { [weak self] in
            guard let self = self else { return }
            while !Task.isCancelled {
                let stillCapturing = await MainActor.run { self.isCapturing }
                if !stillCapturing { break }

                let stats = autoreleasepool {
                    self.captureEngine.refreshFileStats()
                    return self.captureEngine.currentStats
                }

                await MainActor.run {
                    self.captureStats = stats
                }

                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            DebugLog.debug("captureStatsTask: loop ended", source: "AppState")
        }
    }

    private func stopCaptureStatsPolling() {
        DebugLog.debug("stopCaptureStatsPolling() — cancelling task", source: "AppState")
        captureStatsTask?.cancel()
        captureStatsTask = nil
    }

    // MARK: - Stats Update
    private func updateStats() async {
        let stats = await networkMonitor.getInterfaceStats()
        interfaces = stats
        captureStats = captureEngine.currentStats

        // Run pattern recognition
        let newPatterns = patternEngine.analyze(interfaces: stats)
        if !newPatterns.isEmpty {
            patterns.append(contentsOf: newPatterns)
            if patterns.count > 200 {
                patterns.removeFirst(patterns.count - 200)
            }
        }
    }

    // MARK: - Activity Log
    func log(_ message: String, type: ActivityEntry.EntryType) {
        let entry = ActivityEntry(
            timestamp: Date(),
            message: message,
            type: type
        )
        activityLog.insert(entry, at: 0)
        if activityLog.count > 500 {
            activityLog = Array(activityLog.prefix(500))
        }
    }

    // MARK: - Session
    func saveSessionState() {
        DebugLog.debug("saveSessionState() — saving (isMonitoring=\(isMonitoring), \(interfaces.count) interfaces, \(activityLog.count) log entries)", source: "AppState")
        sessionManager.save(
            interfaces: interfaces,
            stats: captureStats,
            activityLog: activityLog,
            isMonitoring: isMonitoring
        )
    }

    private func restoreSession() {
        DebugLog.debug("restoreSession() — attempting restore", source: "AppState")
        if let restored = sessionManager.restore() {
            activityLog = restored.activityLog
            DebugLog.info("restoreSession(): restored \(restored.activityLog.count) log entries, was monitoring=\(restored.isMonitoring)", source: "AppState")
        } else {
            DebugLog.debug("restoreSession(): no saved session found", source: "AppState")
        }
    }
}

// MARK: - Tab Enum
enum AppTab: String, CaseIterable, Identifiable {
    case monitor = "Monitor"
    case interfaces = "Interfaces"
    case capture = "Capture"
    case patterns = "Patterns"
    case settings = "Settings"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .monitor: return "waveform.path.ecg"
        case .interfaces: return "network"
        case .capture: return "internaldrive"
        case .patterns: return "brain"
        case .settings: return "gear"
        }
    }
}
