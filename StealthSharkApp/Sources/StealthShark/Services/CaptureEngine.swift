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
    func startCapture(interfaces: [NetworkInterface], rotationHours: Int = 4) {
        guard let tshark = tsharkPath else {
            DebugLog.error("startCapture(): tshark not found", source: "CaptureEngine")
            return
        }

        // Filter to only meaningful interfaces
        let captureable = interfaces.filter { Self.shouldCapture($0) }
        let skipped = interfaces.count - captureable.count
        DebugLog.info("startCapture(): \(interfaces.count) interfaces → \(captureable.count) captureable (skipped \(skipped) blocked/inactive), rotation=\(rotationHours)h, tshark=\(tshark)", source: "CaptureEngine")
        if skipped > 0 {
            let skippedNames = interfaces.filter { !Self.shouldCapture($0) }.map { $0.name }.joined(separator: ", ")
            DebugLog.debug("startCapture(): skipped: \(skippedNames)", source: "CaptureEngine")
        }

        isCapturing = true
        currentStats.startTime = Date()

        for iface in captureable {
            startCaptureOnInterface(iface.name, tsharkPath: tshark, rotationHours: rotationHours)
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
    private func startCaptureOnInterface(_ interface: String, tsharkPath: String, rotationHours: Int = 4) {
        queue.async { [weak self] in
            guard let self = self else { return }

            let timestamp = ISO8601DateFormatter().string(from: Date())
                .replacingOccurrences(of: ":", with: "-")
            let filename = "capture_\(interface)_\(timestamp).pcapng"
            let filepath = self.captureDir.appendingPathComponent(filename)

            let durationSeconds = rotationHours * 3600
            // tshark filesize is in KB; 3 GB = 3,000,000 KB
            let filesizeKB = 3_000_000

            let process = Process()
            process.executableURL = URL(fileURLWithPath: tsharkPath)
            process.arguments = [
                "-i", interface,
                "-w", filepath.path,
                "-b", "duration:\(durationSeconds)",  // Rotate every N hours
                "-b", "filesize:\(filesizeKB)",        // Rotate at 3 GB
                "-q"                                   // Quiet mode
            ]

            DebugLog.debug("startCaptureOnInterface(\(interface)): cmd=\(tsharkPath) -i \(interface) -w \(filepath.path) -b duration:\(durationSeconds) -b filesize:\(filesizeKB) -q", source: "CaptureEngine")

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

        // Separate: empty files get deleted, old files get archived
        var toArchive: [(url: URL, size: UInt64)] = []
        var deletedCount = 0
        var deletedBytes: UInt64 = 0
        for fileURL in contents where fileURL.pathExtension == "pcapng" {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path) {
                let created = attrs[.creationDate] as? Date ?? Date.distantPast
                let size = attrs[.size] as? UInt64 ?? 0

                if size < 1024 {
                    // Empty files (<1 KB = just pcap header, no packets) — delete
                    try? fm.removeItem(at: fileURL)
                    deletedCount += 1
                    deletedBytes += size
                    DebugLog.debug("cleanupOldCaptures(): deleted empty file \(fileURL.lastPathComponent) (\(size) bytes)", source: "CaptureEngine")
                } else if created < cutoff {
                    // Old files with real data — archive them
                    toArchive.append((fileURL, size))
                }
            }
        }

        var archivedCount = 0
        var archivedBytes: UInt64 = 0
        if !toArchive.isEmpty {
            archivedCount = archiveFiles(toArchive.map { $0.url })
            archivedBytes = toArchive.reduce(0) { $0 + $1.size }
        }

        DebugLog.info("cleanupOldCaptures(): deleted \(deletedCount) empty file(s) (\(formatBytes(deletedBytes))), archived \(archivedCount) old file(s) (\(formatBytes(archivedBytes)))", source: "CaptureEngine")
    }

    /// When disk usage exceeds the limit, archive (compress) the oldest pcap files
    /// into a timestamped .tar.gz archive instead of deleting them.
    /// Returns the number of files archived.
    @discardableResult
    func enforceDiskLimit(maxGB: Int) -> Int {
        guard maxGB > 0 else { return 0 }
        let maxBytes = UInt64(maxGB) * 1_000_000_000
        DebugLog.info("enforceDiskLimit(maxGB=\(maxGB))", source: "CaptureEngine")

        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey]) else {
            DebugLog.warn("enforceDiskLimit(): failed to list \(captureDir.path)", source: "CaptureEngine")
            return 0
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
            DebugLog.debug("enforceDiskLimit(): total \(formatBytes(totalSize)) <= limit \(formatBytes(maxBytes)), no archiving needed", source: "CaptureEngine")
            return 0
        }

        let overBy = totalSize - maxBytes
        DebugLog.warn("enforceDiskLimit(): total \(formatBytes(totalSize)) > limit \(formatBytes(maxBytes)) by \(formatBytes(overBy)), archiving oldest files", source: "CaptureEngine")

        // Sort oldest first and archive until under limit
        files.sort { $0.created < $1.created }
        var toArchive: [URL] = []
        var archivedBytes: UInt64 = 0
        for file in files {
            if totalSize <= maxBytes { break }
            toArchive.append(file.url)
            totalSize -= file.size
            archivedBytes += file.size
        }

        let archivedCount = archiveFiles(toArchive)
        DebugLog.info("enforceDiskLimit(): archived \(archivedCount) file(s) (\(formatBytes(archivedBytes))), now at \(formatBytes(totalSize))", source: "CaptureEngine")
        return archivedCount
    }

    /// Check disk usage and warn if over the threshold. Returns true if a warning was issued.
    @discardableResult
    func checkDiskUsageWarning(thresholdGB: Int = 30) -> Bool {
        let thresholdBytes = UInt64(thresholdGB) * 1_000_000_000
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(at: captureDir, includingPropertiesForKeys: [.fileSizeKey]) else {
            return false
        }

        var totalSize: UInt64 = 0
        for fileURL in contents where fileURL.pathExtension == "pcapng" {
            if let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
               let size = attrs[.size] as? UInt64 {
                totalSize += size
            }
        }

        if totalSize >= thresholdBytes {
            DebugLog.warn("⚠️ Disk usage warning: \(formatBytes(totalSize)) exceeds \(thresholdGB) GB threshold", source: "CaptureEngine")
            return true
        }
        return false
    }

    /// Compress pcap files into a timestamped .tar.gz archive and remove the originals.
    /// Returns the number of files successfully archived.
    private func archiveFiles(_ files: [URL]) -> Int {
        guard !files.isEmpty else { return 0 }

        let archiveDir = captureDir.appendingPathComponent("archives")
        try? FileManager.default.createDirectory(at: archiveDir, withIntermediateDirectories: true)

        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let archivePath = archiveDir.appendingPathComponent("archive_\(timestamp).tar.gz")

        // Build tar command: tar -czf <archive> <files...>
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["-czf", archivePath.path] + files.map { $0.path }

        let errorPipe = Pipe()
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus == 0 {
                // Archive created successfully — remove the original files
                var archivedCount = 0
                for fileURL in files {
                    try? FileManager.default.removeItem(at: fileURL)
                    archivedCount += 1
                }

                // Log archive size
                let archiveSize = (try? FileManager.default.attributesOfItem(atPath: archivePath.path)[.size] as? UInt64) ?? 0
                DebugLog.info("archiveFiles(): created \(archivePath.lastPathComponent) (\(formatBytes(archiveSize))) from \(archivedCount) file(s)", source: "CaptureEngine")
                return archivedCount
            } else {
                let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                DebugLog.error("archiveFiles(): tar failed with exit code \(process.terminationStatus): \(stderr)", source: "CaptureEngine")
                return 0
            }
        } catch {
            DebugLog.error("archiveFiles(): failed to run tar: \(error)", source: "CaptureEngine")
            return 0
        }
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
