import SwiftUI

/// Expandable debug log panel that sits at the bottom of the main window.
/// Collapsed: thin bar with entry count + chevron.
/// Expanded: scrollable log view that grows upward.
struct DebugPanelView: View {
    @ObservedObject private var debugLog = DebugLog.shared
    @State private var isExpanded = false
    @State private var panelHeight: CGFloat = 200
    @State private var minLevel: DebugEntry.Level = .trace
    @State private var autoScroll = true
    @State private var showExportAlert = false
    @State private var exportPath = ""

    private let collapsedHeight: CGFloat = 28
    private let minHeight: CGFloat = 120
    private let maxHeight: CGFloat = 450

    private var filteredEntries: [DebugEntry] {
        debugLog.entries.filter { $0.level.sortOrder <= minLevel.sortOrder }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Drag handle (only visible when expanded)
            if isExpanded {
                Rectangle()
                    .fill(Color.secondary.opacity(0.3))
                    .frame(height: 4)
                    .gesture(
                        DragGesture()
                            .onChanged { value in
                                let newHeight = panelHeight - value.translation.height
                                panelHeight = max(minHeight, min(maxHeight, newHeight))
                            }
                    )
                    .onHover { hovering in
                        if hovering {
                            NSCursor.resizeUpDown.push()
                        } else {
                            NSCursor.pop()
                        }
                    }
            }

            // Header bar (always visible)
            headerBar

            // Log content (only when expanded)
            if isExpanded {
                logContent
                    .frame(height: panelHeight - collapsedHeight - 4)
            }
        }
        .background(Color(NSColor.windowBackgroundColor))
        .overlay(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.secondary.opacity(0.2), lineWidth: 0.5)
        )
        .alert("Log Exported", isPresented: $showExportAlert) {
            Button("OK") {}
        } message: {
            Text("Saved to:\n\(exportPath)")
        }
    }

    // MARK: - Header Bar

    private var headerBar: some View {
        HStack(spacing: 8) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.up")
                        .font(.caption2)
                    Image(systemName: "terminal")
                        .font(.caption)
                    Text("Debug Log")
                        .font(.caption.bold())
                }
            }
            .buttonStyle(.plain)

            if !isExpanded {
                Text("\(debugLog.entries.count) entries")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if let last = debugLog.entries.last {
                    Text("· \(last.source): \(last.message)")
                        .font(.caption2)
                        .foregroundStyle(last.level.color)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }

            Spacer()

            if isExpanded {
                // Level filter
                levelFilter

                Divider().frame(height: 14)

                Button {
                    autoScroll.toggle()
                } label: {
                    Image(systemName: autoScroll ? "arrow.down.circle.fill" : "arrow.down.circle")
                        .foregroundStyle(autoScroll ? .blue : .secondary)
                }
                .buttonStyle(.plain)
                .help("Auto-scroll to latest")

                Button {
                    if let url = debugLog.exportToFile() {
                        exportPath = url.path
                        showExportAlert = true
                    }
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .buttonStyle(.plain)
                .help("Export to file")

                Button {
                    debugLog.clear()
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.plain)
                .help("Clear log")
            }
        }
        .padding(.horizontal, 10)
        .frame(height: collapsedHeight)
        .background(Color(NSColor.controlBackgroundColor))
    }

    // MARK: - Level Filter

    private var levelFilter: some View {
        HStack(spacing: 2) {
            ForEach(DebugEntry.Level.allCases.reversed(), id: \.rawValue) { level in
                Button {
                    minLevel = level
                } label: {
                    Text(level.rawValue)
                        .font(.system(size: 9, weight: .medium, design: .monospaced))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(
                            minLevel == level ? level.color.opacity(0.2) : Color.clear
                        )
                        .foregroundStyle(minLevel == level ? level.color : .secondary)
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Log Content

    private var logContent: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(filteredEntries) { entry in
                        LogRow(entry: entry)
                            .id(entry.id)
                    }
                    if filteredEntries.isEmpty {
                        Text("No log entries (filtered)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .padding(8)
                    }
                }
            }
            .background(Color(NSColor.textBackgroundColor).opacity(0.3))
            .onChange(of: filteredEntries.count) { _, _ in
                if autoScroll, let last = filteredEntries.last {
                    withAnimation {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }
}

// MARK: - Log Row

struct LogRow: View {
    let entry: DebugEntry
    @State private var isHovered = false
    @State private var copied = false

    private var fullLine: String {
        "\(entry.formattedTime) [\(entry.source)] \(entry.level.rawValue) \(entry.message)"
    }

    var body: some View {
        HStack(spacing: 0) {
            Text(entry.formattedTime)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)

            Text("[\(entry.source)]")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)

            Text(entry.level.rawValue)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundStyle(entry.level.color)
                .frame(width: 50, alignment: .leading)

            Text(entry.message)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(entry.level == .error ? entry.level.color : .primary)
                .lineLimit(3)
                .textSelection(.enabled)

            Spacer()

            if copied {
                Text("Copied!")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.green)
                    .padding(.trailing, 4)
            } else if isHovered {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .padding(.trailing, 4)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 1)
        .background(rowBackground)
        .onHover { hovering in
            isHovered = hovering
        }
        .onTapGesture {
            copyToClipboard(fullLine)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                copied = false
            }
        }
        .contextMenu {
            Button("Copy Line") {
                copyToClipboard(fullLine)
            }
        }
    }

    private var rowBackground: some View {
        if entry.level == .error {
            return Color.red.opacity(0.05)
        } else if isHovered {
            return Color.secondary.opacity(0.12)
        } else {
            return Color.clear
        }
    }

    private func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
