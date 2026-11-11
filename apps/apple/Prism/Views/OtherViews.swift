import SwiftUI
import UniformTypeIdentifiers
import PrismKit

// MARK: - SSH

struct SSHKeysView: View {
    @EnvironmentObject var model: AppModel
    @State private var showGenerate = false
    @State private var name = ""
    @State private var comment = ""
    @State private var policy: ApprovalPolicy = .always

    var body: some View {
        NavigationStack {
            List(model.sshKeys) { k in
                VStack(alignment: .leading, spacing: 4) {
                    Text(k.name).font(.headline)
                    Text(k.openssh).font(.system(.caption2, design: .monospaced)).lineLimit(2).foregroundStyle(.secondary)
                    Button("Copy OpenSSH public key") { Clipboard.copy(k.openssh) }.buttonStyle(.borderless)
                }
            }
            .navigationTitle("SSH keys")
            .toolbar { ToolbarItem { Button { showGenerate = true } label: { Label("Generate", systemImage: "plus") } } }
            .sheet(isPresented: $showGenerate) {
                NavigationStack {
                    Form {
                        TextField("Name", text: $name)
                        TextField("Comment (user@host)", text: $comment)
                        Picker("Approval", selection: $policy) { ForEach(ApprovalPolicy.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                        Text("The Ed25519 key is derived on the device and never leaves it.").font(.footnote).foregroundStyle(.secondary)
                    }
                    .formStyle(.grouped)
                    .navigationTitle("Generate key")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showGenerate = false } }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Generate") {
                                showGenerate = false
                                Task { await model.generateSshKey(name: name, comment: comment, policy: policy) }
                            }.disabled(name.isEmpty)
                        }
                    }
                }
                #if os(macOS)
                .frame(minWidth: 400, minHeight: 300)
                #endif
            }
            .overlay { if model.sshKeys.isEmpty { ContentUnavailableView("No SSH keys", systemImage: "terminal") } }
        }
    }
}

// MARK: - Backup (.prism files)

struct PrismFileDocument: FileDocument {
    static let type = UTType(exportedAs: "ch.neutheria.prism.export", conformingTo: .data)
    static var readableContentTypes: [UTType] { [type] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct BackupView: View {
    @EnvironmentObject var model: AppModel
    @State private var exporting = false
    @State private var doc = PrismFileDocument(data: Data())
    @State private var importing = false
    @State private var imported: Data?
    @State private var passphrase = ""
    @State private var mode: ImportMode = .merge
    @State private var done: String?
    @State private var askingExportPass = false
    @State private var exportPass = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Export") {
                    Text("The export is encrypted with your recovery passphrase. Approve it on the device.").font(.footnote)
                    Button("Export vault...") {
                        exportPass = ""; askingExportPass = true
                    }
                }
                Section("Import") {
                    Button("Choose .prism file...") { importing = true }
                    if let imported {
                        Text("\(imported.count) bytes loaded")
                        SecureField("Recovery passphrase", text: $passphrase)
                        Picker("Mode", selection: $mode) { ForEach(ImportMode.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                        if mode == .replace { Text("Replace overwrites the device vault AND seed.").foregroundStyle(.red).font(.footnote) }
                        Button("Import") {
                            Task {
                                if await model.importVault(imported, passphrase: passphrase, mode: mode) { done = "Import complete"; self.imported = nil; passphrase = "" }
                            }
                        }.disabled(passphrase.isEmpty)
                    }
                }
                if let done { Text(done).foregroundStyle(.green) }
            }
            .formStyle(.grouped)
            .navigationTitle("Backup")
            .alert("Recovery passphrase", isPresented: $askingExportPass) {
                SecureField("Passphrase", text: $exportPass)
                Button("Export") {
                    let p = exportPass; exportPass = ""
                    Task { if let d = await model.exportVault(passphrase: p) { doc = PrismFileDocument(data: d); exporting = true } }
                }
                Button("Cancel", role: .cancel) { exportPass = "" }
            } message: { Text("Enter the recovery passphrase set on your Prism.") }
            .fileExporter(isPresented: $exporting, document: doc, contentType: PrismFileDocument.type, defaultFilename: "prism-backup") { result in
                if case .failure(let e) = result { model.lastError = e.localizedDescription } else { done = "Exported" }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [PrismFileDocument.type, .data]) { result in
                switch result {
                case .success(let url):
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    do { imported = try Data(contentsOf: url) } catch { model.lastError = error.localizedDescription }
                case .failure(let e): model.lastError = e.localizedDescription
                }
            }
        }
    }
}

// MARK: - DeviceSettings & paired hosts

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var draft = DeviceSettings()
    @State private var settingRecovery = false
    @State private var rp1 = ""
    @State private var rp2 = ""

    var body: some View {
        Form {
            if case .connected(let info) = model.state {
                Section("Device") {
                    LabeledContent("Firmware", value: info.fwVersion)
                    LabeledContent("Battery", value: "\(info.batteryPct)%\(info.charging ? " (charging)" : "")")
                    LabeledContent("Entries", value: "\(info.entryCount)")
                    Button("Lock device") { Task { await model.lockDevice() } }
                }
                Section("Behaviour") {
                    Stepper("Auto-lock: \(draft.autoLockSecs) s", value: $draft.autoLockSecs, in: 30...3600, step: 30)
                    Picker("When idle", selection: $draft.sleepMode) {
                        Text("Power off").tag(SleepMode.powerOff); Text("Light sleep (stay reachable)").tag(SleepMode.lightSleep)
                    }
                    Picker("Keyboard layout", selection: $draft.keyboardLayout) {
                        Text("US").tag(KeyboardLayout.us); Text("FR AZERTY").tag(KeyboardLayout.frAzerty)
                    }
                    Toggle("Buzzer", isOn: $draft.buzzer)
                    Button("Save settings") { Task { await model.save(draft) } }
                }
                Section("Recovery") {
                    Button("Set recovery passphrase...") { rp1 = ""; rp2 = ""; settingRecovery = true }
                }
                Section("Paired hosts") {
                    ForEach(model.pairedHosts) { h in
                        HStack {
                            VStack(alignment: .leading) { Text(h.label); Text(h.publicKey.prefix(4).map { String(format: "%02x", $0) }.joined()).font(.caption.monospaced()).foregroundStyle(.secondary) }
                            Spacer()
                            Button("Remove", role: .destructive) { Task { await model.removeHost(h) } }.buttonStyle(.borderless)
                        }
                    }
                }
            }
            Section("This device") {
                Button("Disconnect") { Task { await model.disconnect() } }.disabled(!model.isConnected)
                Button("Forget Prism and host key", role: .destructive) { Task { await model.forgetDevice() } }
            }
            if model.usingStub { Section { Text("StubCore active: no encryption. Link PrismFFI.xcframework.").foregroundStyle(.orange) } }
        }
        .formStyle(.grouped)
        .alert("Set recovery passphrase", isPresented: $settingRecovery) {
            SecureField("Passphrase", text: $rp1)
            SecureField("Repeat passphrase", text: $rp2)
            Button("Set") {
                guard !rp1.isEmpty, rp1 == rp2 else { model.lastError = "Passphrases do not match"; return }
                let p = rp1; rp1 = ""; rp2 = ""
                Task { _ = await model.setRecoveryPassphrase(p) }
            }
            Button("Cancel", role: .cancel) { rp1 = ""; rp2 = "" }
        } message: { Text("Used to encrypt exports. Confirm on your Prism.") }
        .navigationTitle("Settings")
        .task { await model.loadSettings(); if let s = model.settings { draft = s } }
    }
}

// MARK: - macOS menu bar

#if os(macOS)
struct MenuBarView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if model.isConnected {
                TextField("Search", text: $query).textFieldStyle(.roundedBorder)
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(model.entries.filter { $0.kind == .password || $0.kind == .totp }
                            .filter { query.isEmpty || $0.title.localizedCaseInsensitiveContains(query) }.prefix(30)) { e in
                            Button {
                                Task {
                                    if e.kind == .totp { if let t = await model.totp(e.id) { Clipboard.copy(t.code) } }
                                    else if let s = await model.reveal(e.id, field: .password) { Clipboard.copy(s) }
                                }
                            } label: {
                                HStack { Image(systemName: e.kind.icon); Text(e.title); Spacer(); Text(e.subtitle).foregroundStyle(.secondary).font(.caption) }
                            }.buttonStyle(.plain).padding(.vertical, 3)
                        }
                    }
                }.frame(height: 220)
                if let b = model.busy { HStack { ProgressView().controlSize(.small); Text(b).font(.caption) } }
                Divider()
                Button("Disconnect") { Task { await model.disconnect() } }
            } else {
                Text(model.state == .connecting ? "Connecting..." : "Not connected")
                Button("Connect") { Task { await model.connect() } }
                if case .pairing(let sas) = model.state { Text("Pairing code \(sas)").font(.headline.monospaced()) }
            }
            Button("Quit Prism") { NSApplication.shared.terminate(nil) }
        }
        .padding(12).frame(width: 320)
    }
}
#endif
