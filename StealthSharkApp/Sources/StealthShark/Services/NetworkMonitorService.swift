import Foundation
import Combine
import SystemConfiguration

/// Service that discovers and monitors network interfaces using system APIs
final class NetworkMonitorService: ObservableObject {
    @Published var interfaces: [NetworkInterface] = []

    private var previousStats: [String: InterfaceSnapshot] = [:]
    private var lastUpdate: Date = .distantPast

    struct InterfaceSnapshot {
        let bytesSent: UInt64
        let bytesRecv: UInt64
        let packetsSent: UInt64
        let packetsRecv: UInt64
        let timestamp: Date
    }

    // MARK: - Interface Discovery
    func discoverInterfaces() {
        DebugLog.debug("discoverInterfaces() — entering", source: "NetworkMonitor")
        var discovered: [NetworkInterface] = []

        // Use getifaddrs to enumerate all interfaces
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        let getResult = getifaddrs(&ifaddr)
        guard getResult == 0, let firstAddr = ifaddr else {
            DebugLog.error("discoverInterfaces(): getifaddrs failed with code \(getResult)", source: "NetworkMonitor")
            return
        }
        defer { freeifaddrs(ifaddr) }

        var interfaceMap: [String: NetworkInterface] = [:]
        var ifaddrCount = 0

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let addr = ptr {
            ifaddrCount += 1
            let name = String(cString: addr.pointee.ifa_name)
            let flags = Int32(addr.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0

            if interfaceMap[name] == nil {
                interfaceMap[name] = NetworkInterface(
                    id: name,
                    name: name,
                    isUp: isUp,
                    ipAddresses: [],
                    bytesSent: 0,
                    bytesRecv: 0,
                    packetsSent: 0,
                    packetsRecv: 0,
                    bytesSentRate: 0,
                    bytesRecvRate: 0,
                    packetsSentRate: 0,
                    packetsRecvRate: 0,
                    hasActivity: false
                )
            }

            // Extract IPv4 address
            let family = addr.pointee.ifa_addr.pointee.sa_family
            if family == UInt8(AF_INET) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(
                    addr.pointee.ifa_addr,
                    socklen_t(addr.pointee.ifa_addr.pointee.sa_len),
                    &hostname, socklen_t(hostname.count),
                    nil, 0, NI_NUMERICHOST
                ) == 0 {
                    let ip = String(cString: hostname)
                    interfaceMap[name]?.ipAddresses.append(ip)
                    DebugLog.trace("  \(name): IPv4 = \(ip)", source: "NetworkMonitor")
                } else {
                    DebugLog.trace("  \(name): getnameinfo failed for IPv4", source: "NetworkMonitor")
                }
            }

            ptr = addr.pointee.ifa_next
        }

        DebugLog.debug("discoverInterfaces(): getifaddrs returned \(ifaddrCount) addr entries, \(interfaceMap.count) unique interfaces", source: "NetworkMonitor")

        // Get I/O stats via netstat parsing (more reliable than sysctl for per-interface)
        let ioStats = getNetworkIOStats()
        DebugLog.debug("discoverInterfaces(): netstat returned stats for \(ioStats.count) interfaces", source: "NetworkMonitor")
        for (name, stats) in ioStats {
            if var iface = interfaceMap[name] {
                iface.bytesSent = stats.bytesSent
                iface.bytesRecv = stats.bytesRecv
                iface.packetsSent = stats.packetsSent
                iface.packetsRecv = stats.packetsRecv

                // Calculate rates
                if let prev = previousStats[name] {
                    let elapsed = Date().timeIntervalSince(prev.timestamp)
                    if elapsed > 0 {
                        iface.bytesSentRate = Double(stats.bytesSent - prev.bytesSent) / elapsed
                        iface.bytesRecvRate = Double(stats.bytesRecv - prev.bytesRecv) / elapsed
                        iface.packetsSentRate = Double(stats.packetsSent - prev.packetsSent) / elapsed
                        iface.packetsRecvRate = Double(stats.packetsRecv - prev.packetsRecv) / elapsed
                        iface.hasActivity = iface.bytesSentRate > 0 || iface.bytesRecvRate > 0
                    }
                }

                previousStats[name] = InterfaceSnapshot(
                    bytesSent: stats.bytesSent,
                    bytesRecv: stats.bytesRecv,
                    packetsSent: stats.packetsSent,
                    packetsRecv: stats.packetsRecv,
                    timestamp: Date()
                )

                interfaceMap[name] = iface
            } else {
                DebugLog.trace("  netstat returned stats for '\(name)' but not in getifaddrs map", source: "NetworkMonitor")
            }
        }

        discovered = Array(interfaceMap.values).sorted { a, b in
            // Sort: active first, then alphabetical
            if a.isUp != b.isUp { return a.isUp && !b.isUp }
            return a.name < b.name
        }

        interfaces = discovered
        lastUpdate = Date()
        DebugLog.debug("discoverInterfaces(): done — \(discovered.count) interfaces, \(discovered.filter(\.isUp).count) up, \(discovered.filter(\.hasActivity).count) active", source: "NetworkMonitor")
    }

    // MARK: - Get Updated Stats
    func getInterfaceStats() async -> [NetworkInterface] {
        discoverInterfaces()
        return interfaces
    }

    // MARK: - Network I/O via nettop/netstat
    private struct IOStats {
        let bytesSent: UInt64
        let bytesRecv: UInt64
        let packetsSent: UInt64
        let packetsRecv: UInt64
    }

    private func getNetworkIOStats() -> [String: IOStats] {
        var results: [String: IOStats] = [:]

        // Use netstat -ib for per-interface byte counts
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-ib"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            // Timeout: if netstat doesn't exit in 5 seconds, kill it
            let deadline = Date().addingTimeInterval(5)
            while task.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if task.isRunning {
                DebugLog.warn("getNetworkIOStats(): netstat timed out after 5s, killing", source: "NetworkMonitor")
                task.terminate()
                return results
            }

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let exitCode = task.terminationStatus
            DebugLog.trace("getNetworkIOStats(): netstat -ib exited with code \(exitCode)", source: "NetworkMonitor")

            guard let output = String(data: data, encoding: .utf8) else {
                DebugLog.warn("getNetworkIOStats(): failed to decode netstat output as UTF-8", source: "NetworkMonitor")
                return results
            }

            // Parse netstat output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            let lines = output.components(separatedBy: "\n")
            DebugLog.trace("getNetworkIOStats(): parsing \(lines.count) lines from netstat", source: "NetworkMonitor")
            var parseErrors = 0
            for line in lines.dropFirst() { // Skip header
                let cols = line.split(separator: " ", omittingEmptySubsequences: true)
                    .map(String.init)
                guard cols.count >= 10 else { continue }

                let name = cols[0]
                // Skip duplicate lines (netstat shows one per address)
                if results[name] != nil { continue }

                guard let ipkts = UInt64(cols[4]),
                      let ibytes = UInt64(cols[6]),
                      let opkts = UInt64(cols[7]),
                      let obytes = UInt64(cols[9]) else {
                    parseErrors += 1
                    continue
                }

                results[name] = IOStats(
                    bytesSent: obytes,
                    bytesRecv: ibytes,
                    packetsSent: opkts,
                    packetsRecv: ipkts
                )
            }
            if parseErrors > 0 {
                DebugLog.warn("getNetworkIOStats(): \(parseErrors) lines failed to parse", source: "NetworkMonitor")
            }
        } catch {
            DebugLog.error("getNetworkIOStats(): failed to run netstat: \(error)", source: "NetworkMonitor")
        }

        return results
    }
}
