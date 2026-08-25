import Foundation

/// Manages tshark packet capture processes across multiple interfaces
final class CaptureEngine: ObservableObject {
    @Published var currentStats = CaptureStats()
    @Published var isCapturing = false

    private var captureProcesses: [String: Process] = [:]
    private var captureDir: URL
    private let queue = DispatchQueue(label: "com.stealthshark.capture", qos: .userInitiated)

    init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        captureDir = appSupport.appendingPathComponent("StealthShark/pcap_captures")
        try? FileManager.default.createDirectory(at: captureDir, withIntermediateDirectories: true)
        DebugLog.info("CaptureEngine init — captureDir: \(captureDir.path)", source: "CaptureEngine")
    }

    // MARK: - TShark Path Discovery
    private var tsharkPath: String? {
        let paths = [
            "/opt/homebrew/bin/tshark",
            "/usr/local/bin/tshark",
            "/usr/bin/tshark"
        ]
        let found = paths.first { FileManager.default.fileExists(atPath: $0) }
        if let found = found {
            DebugLog.debug("tsharkPath: found at \(found)", source: "CaptureEngine")
        } else {
            DebugLog.warn("tsharkPath: not found in \(paths)", source: "CaptureEngine")
        }
        return found
    }

    var isTSharkAvailable: Bool {
        tsharkPath != nil
    }

    // MARK: - Capture Control
    func startCapture(interfaces: [NetworkInterface]) {
        guard let tshark = tsharkPath else {
            DebugLog.error("startCapture(): tshark not found", source: "CaptureEngine")
            return
        }

        DebugLog.info("startCapture(): \(interfaces.count) interfaces, tshark=\(tshark)", source: "CaptureEngine")
        isCapturing = true
        currentStats.startTime = Date()

        for iface in interfaces {
            startCaptureOnInterface(iface.name, tsharkPath: tshark)
        }

        currentStats.activeCaptureCount = captureProcesses.count
        DebugLog.debug("startCapture(): dispatched \(interfaces.count) capture tasks", source: "CaptureEngine")
    }

    func stopCapture() {
        DebugLog.info("stopCapture() — entering", source: "CaptureEngine")
        // Use async to avoid potential deadlock if called from within the queue
        queue.async { [weak self] in
            guard let self = self else { return }
            let count = self.captureProcesses.count
            for (name, process) in self.captureProcesses {
                process.terminate()
                DebugLog.debug("stopCapture(): terminated tshark on \(name) (pid=\(process.processIdentifier))", source: "CaptureEngine")
            }
            self.captureProcesses.removeAll()
            DebugLog.info("stopCapture(): stopped \(count) capture process(es)", source: "CaptureEngine")
        }
        isCapturing = false
        currentStats.activeCaptureCount = 0
    }

    func stopCapture(interface: String) {
        DebugLog.info("stopCapture(interface=\(interface))", source: "CaptureEngine")
        queue.async { [weak self] in
            guard let self = self else { return }
            if let process = self.captureProcesses[interface] {
                process.terminate()
                self.captureProcesses.removeValue(forKey: interface)
                DebugLog.debug("stopCapture(\(interface)): terminated pid=\(process.processIdentifier)", source: "CaptureEngine")
            } else {
                DebugLog.warn("stopCapture(\(interface)): no process found", source: "CaptureEngine")
            }
        }
        currentStats.activeCaptureCount = captureProcesses.count
    }

    // MARK: - Per-Interface Capture
    private func startCaptureOnInterface(_ interface: String, tsharkPath: String) {
        queue.async { [weak self] in
            guard let self = self else { return }

            let timestamp = ISO8601DateFormatter().string(from: Date())
                .replacingOccurrences(of: ":", with: "-")
            let filename = "capture_\(interface)_\(timestamp).pcapng"
            let filepath = self.captureDir.appendingPathComponent(filename)

            let process = Process()
            process.executableURL = URL(fileURLWithPath: tsharkPath)
            process.arguments = [
                "-i", interface,
                "-w", filepath.path,
                "-b", "duration:3600",    // Rotate every hour
                "-b", "filesize:102400",  // Rotate at 100MB
                "-q"                       // Quiet mode
            ]

            DebugLog.debug("startCaptureOnInterface(\(interface)): cmd=\(tsharkPath) -i \(interface) -w \(filepath.path) -b duration:3600 -b filesize:102400 -q", source: "CaptureEngine")

            // Capture stdout/stderr for packet counts
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            process.terminationHandler = { [weak self] proc in
                let exitCode = proc.terminationStatus
                DebugLog.info("tshark[\(interface)] terminated with exit code \(exitCode)", source: "CaptureEngine")

                // Read stderr for diagnostics
                let stderrData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                if let stderrStr = String(data: stderrData, encoding: .utf8), !stderrStr.isEmpty {
                    DebugLog.warn("tshark[\(interface)] stderr: \(stderrStr.trimmingCharacters(in: .whitespacesAndNewlines))", source: "CaptureEngine")
                }

                DispatchQueue.main.async {
                    self?.captureProcesses.removeValue(forKey: interface)
                    self?.currentStats.activeCaptureCount = self?.captureProcesses.count ?? 0
                }
            }

            do {
                try process.run()
                self.captureProcesses[interface] = process
                DebugLog.info("tshark[\(interface)] started — pid=\(process.processIdentifier), file=\(filename)", source: "CaptureEngine")

                let file = CaptureFile(
                    filename: filename,
                    interface: interface,
                    startTime: Date(),
                    size: 0,
                    packetCount: 0
                )

                DispatchQueue.main.async {
                    self.currentStats.captureFiles.append(file)
                    // Cap to prevent unbounded growth
                    if self.currentStats.captureFiles.count > 100 {
                        self.currentStats.captureFiles.removeFirst(self.currentStats.captureFiles.count - 100)
                    }
                    self.currentStats.activeCaptureCount = self.captureProcesses.count
                }
            } catch {
                DebugLog.error("startCaptureOnInterface(\(interface)): failed to run tshark: \(error)", source: "CaptureEngine")
            }
        }
    }

    // MARK: - Stats Refresh
    func refreshFileStats() {
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.fileSizeKey]) else {
            DebugLog.warn("refreshFileStats(): failed to list \(captureDir.path)", source: "CaptureEngine")
            return
        }

        var totalBytes: UInt64 = 0
        var fileCount = 0
        for fileURL in contents where fileURL.pathExtension == "pcapng" {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
               let size = attrs[.size] as? UInt64 {
                totalBytes += size
                fileCount += 1
            }
        }
        currentStats.totalBytes = totalBytes
        DebugLog.trace("refreshFileStats(): \(fileCount) pcapng files, \(totalBytes) bytes total", source: "CaptureEngine")
    }

    // MARK: - Cleanup
    func cleanupOldCaptures(olderThan days: Int = 7) {
        DebugLog.info("cleanupOldCaptures(olderThan=\(days) days)", source: "CaptureEngine")
        let fm = FileManager.default
        let cutoff = Date().addingTimeInterval(-Double(days * 86400))

        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.creationDateKey]) else {
            DebugLog.warn("cleanupOldCaptures(): failed to list \(captureDir.path)", source: "CaptureEngine")
            return
        }

        var deletedCount = 0
        for fileURL in contents {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
               let created = attrs[.creationDate] as? Date,
               created < cutoff {
                try? fm.removeItem(at: fileURL)
                deletedCount += 1
                DebugLog.debug("cleanupOldCaptures(): deleted \(fileURL.lastPathComponent)", source: "CaptureEngine")
            }
        }
        DebugLog.info("cleanupOldCaptures(): deleted \(deletedCount) file(s)", source: "CaptureEngine")
    }
}
