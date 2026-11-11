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
        if let msg = model.busy {
            HStack(spacing: 12) {
                ProgressView()
                Text(msg).font(.callout.weight(.medium))
            }
            .padding(14)
            .background(.regularMaterial, in: Capsule())
            .padding(.bottom, 24)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
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

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "key.radiowaves.forward").font(.system(size: 64)).foregroundStyle(.tint)
            Text("Prism").font(.largeTitle.bold())
            switch model.state {
            case .pairing(let sas):
                VStack(spacing: 12) {
                    Text("Pairing code").font(.headline)
                    Text(sas).font(.system(size: 48, weight: .bold, design: .monospaced)).kerning(6)
                    Text("Check that the same code is shown on your Prism, then tap Confirm on the device.")
                        .multilineTextAlignment(.center).foregroundStyle(.secondary)
                    ProgressView()
                }
            case .connecting:
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Looking for your Prism...").foregroundStyle(.secondary)
                    if !model.isPaired {
                        Text("On the device: Settings > Pair new host.").font(.footnote).foregroundStyle(.secondary)
                    }
                }
            case .failed(let msg):
                Text(msg).foregroundStyle(.red).multilineTextAlignment(.center)
                connectButton
            default:
                if let name = model.deviceName { Text("Last device: \(name)").foregroundStyle(.secondary) }
                connectButton
                if !model.isPaired {
                    Text("To pair a new device open Settings > Pair new host on your Prism first.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
            }
            if model.usingStub {
                Text("Running with the insecure StubCore (PrismFFI.xcframework not linked).")
                    .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
            }
        }
        .padding(32)
        .frame(maxWidth: 480)
    }

    var connectButton: some View {
        Button { Task { await model.connect() } } label: {
            Label(model.isPaired ? "Connect" : "Pair with Prism", systemImage: "antenna.radiowaves.left.and.right")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent).controlSize(.large)
    }
}
