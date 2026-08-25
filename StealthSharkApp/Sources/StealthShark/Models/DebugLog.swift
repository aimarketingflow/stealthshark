import Foundation
import SwiftUI
import Combine

// MARK: - Debug Entry

struct DebugEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let source: String
    let level: Level
    let message: String

    enum Level: String, CaseIterable {
        case trace = "TRACE"
        case debug = "DEBUG"
        case info = "INFO"
        case warn = "WARN"
        case error = "ERROR"

        var color: Color {
            switch self {
            case .trace: return .secondary
            case .debug: return .primary
            case .info: return .blue
            case .warn: return .orange
            case .error: return .red
            }
        }

        var sortOrder: Int {
            switch self {
            case .error: return 0
            case .warn: return 1
            case .info: return 2
            case .debug: return 3
            case .trace: return 4
            }
        }
    }

    var formattedTime: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: timestamp)
    }
}

// MARK: - Debug Log Manager

/// Thread-safe singleton logger. Services and views can call `DebugLog.log()` from any thread.
/// Entries are collected in a thread-safe buffer and flushed to the @Published array on the main thread.
final class DebugLog: ObservableObject {
    static let shared = DebugLog()

    @Published private(set) var entries: [DebugEntry] = []

    private let lock = NSLock()
    private var buffer: [DebugEntry] = []
    private var flushTimer: DispatchSourceTimer?
    private let maxEntries = 1000

    private init() {
        startFlushTimer()
    }

    // MARK: - Public Logging API

    static func trace(_ message: String, source: String = "AppState") {
        shared.append(level: .trace, source: source, message: message)
    }

    static func debug(_ message: String, source: String = "AppState") {
        shared.append(level: .debug, source: source, message: message)
    }

    static func info(_ message: String, source: String = "AppState") {
        shared.append(level: .info, source: source, message: message)
    }

    static func warn(_ message: String, source: String = "AppState") {
        shared.append(level: .warn, source: source, message: message)
    }

    static func error(_ message: String, source: String = "AppState") {
        shared.append(level: .error, source: source, message: message)
    }

    // MARK: - Append (thread-safe)

    private func append(level: DebugEntry.Level, source: String, message: String) {
        let entry = DebugEntry(timestamp: Date(), source: source, level: level, message: message)
        lock.lock()
        buffer.append(entry)
        if buffer.count > maxEntries {
            buffer.removeFirst(buffer.count - maxEntries)
        }
        lock.unlock()
    }

    // MARK: - Flush to Main Thread

    private func startFlushTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .milliseconds(100))
        timer.setEventHandler { [weak self] in
            self?.flush()
        }
        timer.resume()
        flushTimer = timer
    }

    private func flush() {
        lock.lock()
        guard !buffer.isEmpty else {
            lock.unlock()
            return
        }
        let toFlush = buffer
        buffer.removeAll()
        lock.unlock()

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.entries.append(contentsOf: toFlush)
            if self.entries.count > self.maxEntries {
                self.entries.removeFirst(self.entries.count - self.maxEntries)
            }
        }
    }

    // MARK: - Controls

    func clear() {
        DispatchQueue.main.async {
            self.entries.removeAll()
        }
    }

    func copyAll() -> String {
        entries.map { "\($0.formattedTime) [\($0.source)] \($0.level.rawValue) \($0.message)" }
            .joined(separator: "\n")
    }

    /// Export full log to a file in Application Support
    func exportToFile() -> URL? {
        let content = copyAll()
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let logDir = appSupport.appendingPathComponent("StealthShark/logs")
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)

        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let filename = "debug_\(f.string(from: Date())).log"
        let fileURL = logDir.appendingPathComponent(filename)

        do {
            try content.write(to: fileURL, atomically: true, encoding: .utf8)
            return fileURL
        } catch {
            return nil
        }
    }
}
