import Foundation

/// Handles persistence of session state (auto-save, crash recovery)
final class SessionManager {
    private let sessionFile: URL
    private let prefsFile: URL

    init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let baseDir = appSupport.appendingPathComponent("StealthShark/sessions")
        try? FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        sessionFile = baseDir.appendingPathComponent("session_state.json")
        prefsFile = baseDir.appendingPathComponent("preferences.json")
        DebugLog.debug("SessionManager init — sessionFile: \(sessionFile.path)", source: "SessionManager")
    }

    // MARK: - Session State
    func save(interfaces: [NetworkInterface], stats: CaptureStats, activityLog: [ActivityEntry], isMonitoring: Bool) {
        let state = SessionState(
            isMonitoring: isMonitoring,
            lastActive: Date(),
            interfaceNames: interfaces.map(\.name),
            activityLog: activityLog
        )

        do {
            let data = try JSONEncoder().encode(state)
            try data.write(to: sessionFile, options: .atomic)
            DebugLog.debug("save(): wrote \(data.count) bytes to \(sessionFile.lastPathComponent) (\(activityLog.count) log entries)", source: "SessionManager")
        } catch {
            DebugLog.error("save(): failed to save session: \(error)", source: "SessionManager")
        }
    }

    func restore() -> SessionState? {
        guard FileManager.default.fileExists(atPath: sessionFile.path) else {
            DebugLog.debug("restore(): no session file at \(sessionFile.path)", source: "SessionManager")
            return nil
        }
        do {
            let data = try Data(contentsOf: sessionFile)
            let state = try JSONDecoder().decode(SessionState.self, from: data)
            DebugLog.info("restore(): loaded session (was monitoring=\(state.isMonitoring), \(state.interfaceNames.count) interfaces)", source: "SessionManager")
            return state
        } catch {
            DebugLog.error("restore(): failed to decode session: \(error)", source: "SessionManager")
            return nil
        }
    }

    // MARK: - Preferences
    struct Preferences: Codable {
        var autoStartCapture: Bool = true
        var minimizeToMenuBar: Bool = true
        var captureRotationHours: Int = 1
        var maxDiskUsageGB: Int = 50
        var cleanupAfterDays: Int = 7
        var monitoredInterfaces: [String] = [] // empty = all
        var autoRestartEnabled: Bool = true
        var autoRestartHours: Int = 4
        var autoRestartMinutes: Int = 0
        var autoRestartCaptureGB: Int = 2
    }

    func loadPreferences() -> Preferences {
        guard FileManager.default.fileExists(atPath: prefsFile.path) else {
            DebugLog.debug("loadPreferences(): no prefs file, returning defaults", source: "SessionManager")
            return Preferences()
        }
        do {
            let data = try Data(contentsOf: prefsFile)
            let prefs = try JSONDecoder().decode(Preferences.self, from: data)
            DebugLog.debug("loadPreferences(): loaded prefs (autoStart=\(prefs.autoStartCapture), rotation=\(prefs.captureRotationHours)h, restart=\(prefs.autoRestartEnabled ? "on" : "off") \(prefs.autoRestartHours)h\(prefs.autoRestartMinutes)m or \(prefs.autoRestartCaptureGB)GB)", source: "SessionManager")
            return prefs
        } catch {
            DebugLog.warn("loadPreferences(): failed to decode, returning defaults: \(error)", source: "SessionManager")
            return Preferences()
        }
    }

    func savePreferences(_ prefs: Preferences) {
        do {
            let data = try JSONEncoder().encode(prefs)
            try data.write(to: prefsFile, options: .atomic)
            DebugLog.info("savePreferences(): wrote \(data.count) bytes", source: "SessionManager")
        } catch {
            DebugLog.error("savePreferences(): failed: \(error)", source: "SessionManager")
        }
    }

    /// Convenience helper to check if auto-restart by duration is enabled and has a non-zero duration.
    func isAutoRestartDurationEnabled(prefs: Preferences) -> Bool {
        prefs.autoRestartEnabled && (prefs.autoRestartHours > 0 || prefs.autoRestartMinutes > 0)
    }

    /// Total duration in seconds for auto-restart.
    func autoRestartDurationSeconds(prefs: Preferences) -> TimeInterval {
        TimeInterval(prefs.autoRestartHours * 3600 + prefs.autoRestartMinutes * 60)
    }
}
