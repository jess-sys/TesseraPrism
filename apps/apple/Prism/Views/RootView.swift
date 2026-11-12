import SwiftUI
import PrismKit

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.isConnected {
                MainTabs()
            } else {
                ConnectView()
            }
        }
        .overlay(alignment: .bottom) { BusyBanner() }
        .alert("Error", isPresented: Binding(get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } })) {
            Button("OK") { model.lastError = nil }
        } message: { Text(model.lastError ?? "") }
    }
}

struct BusyBanner: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Group {
            if let activity = model.activity {
                PrismActivityView(activity)
                    .frame(maxWidth: 320)
                    .padding(.vertical, 8)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                    .shadow(color: .black.opacity(0.15), radius: 16, y: 6)
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.smooth, value: model.activity)
    }
}

struct MainTabs: View {
    var body: some View {
        TabView {
            EntryListView().tabItem { Label("Vault", systemImage: "key.fill") }
            SSHKeysView().tabItem { Label("SSH", systemImage: "terminal") }
            BackupView().tabItem { Label("Backup", systemImage: "externaldrive") }
            NavigationStack { SettingsView() }.tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}

// MARK: - Connect / pair

struct ConnectView: View {
    @EnvironmentObject var model: AppModel
    @State private var showCache = false

    var body: some View {
        VStack(spacing: 24) {
            PrismBrandHeader(logoSize: 88, subtitle: model.state == .disconnected ? "Your offline vault" : nil)
                .padding(.bottom, 4)
            switch model.state {
            case .pairing(let sas):
                PrismActivityView(.pairing(code: sas))
            case .connecting:
                VStack(spacing: 12) {
                    PrismActivityView(.searching)
                    if !model.isPaired {
                        Text("On the device: Settings > Pair new host.").font(.footnote).foregroundStyle(.secondary)
                    }
                }
            case .failed(let msg):
                PrismActivityView(.failure(msg))
                connectButton
            default:
                if let name = model.deviceName { Text("Last device: \(name)").foregroundStyle(.secondary) }
                connectButton
                if !model.isPaired {
                    Text("To pair a new device open Settings > Pair new host on your Prism first.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
            }
            if let m = model.cacheMeta {
                Button { showCache = true } label: { Label("Cached passwords (\(m.count))", systemImage: "lock.doc") }
                    .buttonStyle(.bordered)
            }
            if model.usingStub {
                Text("Running with the insecure StubCore (PrismFFI.xcframework not linked).")
                    .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
            }
        }
        .padding(32)
        .frame(maxWidth: 480)
        .onAppear { model.refreshCacheState() }
        .sheet(isPresented: $showCache) { CachedPasswordsView() }
    }

    var connectButton: some View {
        Button { Task { await model.connect() } } label: {
            Label(model.isPaired ? "Connect" : "Pair with Prism", systemImage: "antenna.radiowaves.left.and.right")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent).controlSize(.large)
    }
}
