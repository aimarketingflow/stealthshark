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

    // MARK: - Interface Filtering
    /// Interfaces that should never be captured on — virtual/firewall/bridge
    /// interfaces with no real network traffic.
    private static let blockedInterfaces: Set<String> = [
        "pflog0", "llw0", "bridge0", "ap1", "anpi0", "anpi1", "awdl0",
        "lo0", "gif0", "stf0", "XHC20", "utun6", "utun7", "utun8", "utun9"
    ]

    /// Returns true if this interface is worth capturing on.
    static func shouldCapture(_ iface: NetworkInterface) -> Bool {
        guard iface.isUp else { return false }
        guard !blockedInterfaces.contains(iface.name) else { return false }
        // Must have at least one non-link-local IP address
        let hasRealIP = iface.ipAddresses.contains { ip in
            !ip.hasPrefix("fe80") && !ip.hasPrefix("169.254") && ip != "::1" && ip != "127.0.0.1"
        }
        return hasRealIP
    }

    // MARK: - Capture Control
    func startCapture(interfaces: [NetworkInterface]) {
        guard let tshark = tsharkPath else {
            DebugLog.error("startCapture(): tshark not found", source: "CaptureEngine")
            return
        }

        // Filter to only meaningful interfaces
        let captureable = interfaces.filter { Self.shouldCapture($0) }
        let skipped = interfaces.count - captureable.count
        DebugLog.info("startCapture(): \(interfaces.count) interfaces → \(captureable.count) captureable (skipped \(skipped) blocked/inactive), tshark=\(tshark)", source: "CaptureEngine")
        if skipped > 0 {
            let skippedNames = interfaces.filter { !Self.shouldCapture($0) }.map { $0.name }.joined(separator: ", ")
            DebugLog.debug("startCapture(): skipped: \(skippedNames)", source: "CaptureEngine")
        }

        isCapturing = true
        currentStats.startTime = Date()

        for iface in captureable {
            startCaptureOnInterface(iface.name, tsharkPath: tshark)
        }

        currentStats.activeCaptureCount = captureProcesses.count
        DebugLog.debug("startCapture(): dispatched \(captureable.count) capture tasks", source: "CaptureEngine")
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

        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.creationDateKey, .fileSizeKey]) else {
            DebugLog.warn("cleanupOldCaptures(): failed to list \(captureDir.path)", source: "CaptureEngine")
            return
        }

        var deletedCount = 0
        var deletedBytes: UInt64 = 0
        for fileURL in contents where fileURL.pathExtension == "pcapng" {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path) {
                let created = attrs[.creationDate] as? Date ?? Date.distantPast
                let size = attrs[.size] as? UInt64 ?? 0

                // Delete if older than cutoff OR if empty (<1 KB = just pcap header, no packets)
                if created < cutoff || size < 1024 {
                    try? fm.removeItem(at: fileURL)
                    deletedCount += 1
                    deletedBytes += size
                    if size < 1024 {
                        DebugLog.debug("cleanupOldCaptures(): deleted empty file \(fileURL.lastPathComponent) (\(size) bytes)", source: "CaptureEngine")
                    } else {
                        DebugLog.debug("cleanupOldCaptures(): deleted old file \(fileURL.lastPathComponent)", source: "CaptureEngine")
                    }
                }
            }
        }
        DebugLog.info("cleanupOldCaptures(): deleted \(deletedCount) file(s), freed \(formatBytes(deletedBytes))", source: "CaptureEngine")
    }

    /// Enforce a maximum disk usage by deleting oldest pcap files until under the limit.
    func enforceDiskLimit(maxGB: Int) {
        guard maxGB > 0 else { return }
        let maxBytes = UInt64(maxGB) * 1_000_000_000
        DebugLog.info("enforceDiskLimit(maxGB=\(maxGB))", source: "CaptureEngine")

        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey]) else {
            DebugLog.warn("enforceDiskLimit(): failed to list \(captureDir.path)", source: "CaptureEngine")
            return
        }

        // Build list of pcap files with size and creation date
        var files: [(url: URL, size: UInt64, created: Date)] = []
        var totalSize: UInt64 = 0
        for fileURL in contents where fileURL.pathExtension == "pcapng" {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path) {
                let size = attrs[.size] as? UInt64 ?? 0
                let created = attrs[.creationDate] as? Date ?? Date.distantPast
                files.append((fileURL, size, created))
                totalSize += size
            }
        }

        if totalSize <= maxBytes {
            DebugLog.debug("enforceDiskLimit(): total \(formatBytes(totalSize)) <= limit \(formatBytes(maxBytes)), no cleanup needed", source: "CaptureEngine")
            return
        }

        DebugLog.warn("enforceDiskLimit(): total \(formatBytes(totalSize)) > limit \(formatBytes(maxBytes)), deleting oldest files", source: "CaptureEngine")

        // Sort oldest first and delete until under limit
        files.sort { $0.created < $1.created }
        var deletedCount = 0
        var freedBytes: UInt64 = 0
        for file in files {
            if totalSize <= maxBytes { break }
            try? fm.removeItem(at: file.url)
            totalSize -= file.size
            freedBytes += file.size
            deletedCount += 1
        }
        DebugLog.info("enforceDiskLimit(): deleted \(deletedCount) file(s), freed \(formatBytes(freedBytes)), now at \(formatBytes(totalSize))", source: "CaptureEngine")
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var size = Double(bytes)
        var unitIdx = 0
        while size > 1024 && unitIdx < units.count - 1 {
            size /= 1024
            unitIdx += 1
        }
        return String(format: "%.1f %@", size, units[unitIdx])
    }
}
