#if os(macOS)
import AppKit
import SwiftUI
import PrismKit

/// Floating, non-activating HUD showing the state of an SSH sign-in handled by `prism agent`.
///
/// IPC with the agent (a plain CLI process) goes through `~/.prism/hud`, which the sandboxed app
/// may use via a home-relative temporary-exception entitlement:
///  - `agent-status.json` (agent -> app): {seq, state, host, title, message, ts}
///  - `agent-ack`         (app -> agent): the seq now on screen (tells the agent not to fall back)
///  - `agent-cancel`      (app -> agent): the seq to give up on (Cancel button)
@MainActor
final class AgentHUDController {
    static let shared = AgentHUDController()

    struct Status: Decodable, Equatable {
        var seq: UInt64
        var state: String
        var host: String?
        var title: String?
        var message: String?
        var ts: Double
    }

    /// `~/.prism/hud` in the real home (the sandbox remaps NSHomeDirectory; the entitlement
    /// `temporary-exception.files.home-relative-path.read-write` grants this folder only).
    private let dir: URL? = {
        guard let pw = getpwuid(getuid()), let home = pw.pointee.pw_dir else { return nil }
        let d = URL(fileURLWithPath: String(cString: home)).appendingPathComponent(".prism/hud", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()
    private var timer: Timer?
    private var panel: NSPanel?
    private let model = AgentHUDModel()
    private var last: Status?
    private var lastStamp: Date?
    private var dismissedSeq: UInt64?
    private var hideTask: Task<Void, Never>?

    func start() {
        guard timer == nil, dir != nil else { return }
        // Launched by `prism agent` just to show the HUD: don't leave the main window open.
        if CommandLine.arguments.contains("--background") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                for w in NSApp.windows where !(w is NSPanel) && w.styleMask.contains(.titled) && w.isVisible { w.close() }
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
    }

    private func poll() {
        guard let url = dir?.appendingPathComponent("agent-status.json") else { return }
        let stamp = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        guard stamp != lastStamp else { return }
        lastStamp = stamp
        guard let data = try? Data(contentsOf: url), let st = try? JSONDecoder().decode(Status.self, from: data) else { return }
        guard st != last else { return }
        last = st
        apply(st)
    }

    private func apply(_ st: Status) {
        // Ignore leftovers (agent died mid-request) and requests the user already cancelled.
        guard abs(Date().timeIntervalSince1970 - st.ts) < 120, st.seq != dismissedSeq else { return }
        let host = st.host ?? "server"
        let activity: PrismActivity
        var detail: String?
        var cancellable = false
        var autoHide: TimeInterval?
        switch st.state {
        case "searching": activity = .searching; cancellable = true
        case "unlock": activity = .unlock; cancellable = true
        case "approve": activity = .approve; detail = "SSH sign-in to \(host)"
        case "success": activity = .success(st.title ?? "Signed in to \(host)"); autoHide = 1.5
        case "failure": activity = .failure(st.title ?? "SSH sign-in failed"); detail = st.message; autoHide = 3
        default: hide(); return
        }
        hideTask?.cancel()
        model.seq = st.seq
        model.activity = activity
        model.detail = detail
        model.cancellable = cancellable
        model.onCancel = { [weak self] in self?.cancel(st.seq) }
        show()
        try? String(st.seq).write(to: dir!.appendingPathComponent("agent-ack"), atomically: true, encoding: .utf8)
        if let autoHide {
            hideTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(autoHide * 1_000_000_000))
                if !Task.isCancelled { self?.hide() }
            }
        }
    }

    private func cancel(_ seq: UInt64) {
        dismissedSeq = seq
        if let dir { try? String(seq).write(to: dir.appendingPathComponent("agent-cancel"), atomically: true, encoding: .utf8) }
        hide()
    }

    private func show() {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        // A hidden app (e.g. launched with `open -j`) never shows its windows: unhide, but
        // without activating, so the terminal keeps focus.
        if NSApp.isHidden { NSApp.unhideWithoutActivation() }
        if let host = panel.contentView {
            host.layoutSubtreeIfNeeded()
            var size = host.fittingSize
            if size.width < 50 || size.height < 50 { size = NSSize(width: 300, height: 200) }
            panel.setContentSize(size)
            if let f = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame {
                panel.setFrameOrigin(NSPoint(x: f.maxX - size.width - 16, y: f.maxY - size.height - 12))
            }
        }
        panel.orderFrontRegardless()
    }

    private func hide() {
        hideTask?.cancel()
        panel?.orderOut(nil)
    }

    private func makePanel() -> NSPanel {
        let p = NSPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        p.isFloatingPanel = true
        p.level = .statusBar
        p.hidesOnDeactivate = false
        p.backgroundColor = .clear
        p.isOpaque = false
        p.hasShadow = true
        p.isReleasedWhenClosed = false
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        p.contentView = NSHostingView(rootView: AgentHUDView(model: model).prismBranded())
        return p
    }
}

@MainActor
final class AgentHUDModel: ObservableObject {
    @Published var activity: PrismActivity = .searching
    @Published var detail: String?
    @Published var cancellable = false
    var seq: UInt64 = 0
    var onCancel: () -> Void = {}
}

struct AgentHUDView: View {
    @ObservedObject var model: AgentHUDModel
    var body: some View { AgentHUDCard(activity: model.activity, detail: model.detail, cancellable: model.cancellable, onCancel: model.onCancel) }
}

/// The HUD's visuals (also used for previews and snapshots).
struct AgentHUDCard: View {
    let activity: PrismActivity
    var detail: String?
    var cancellable = false
    var onCancel: () -> Void = {}

    var body: some View {
        VStack(spacing: 4) {
            PrismActivityView(activity, detail: detail)
                .scaleEffect(0.7)
                .frame(height: 150)
            if cancellable {
                Button("Cancel", role: .cancel, action: onCancel)
                    .controlSize(.small)
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 6)
        .padding(.bottom, cancellable ? 14 : 6)
        .frame(width: 280)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
        .padding(10) // room for the shadow
    }
}

#Preview("HUD approve") { AgentHUDCard(activity: .approve, detail: "SSH sign-in to github.com").padding() }
#Preview("HUD searching") { AgentHUDCard(activity: .searching, cancellable: true).padding() }
#endif
