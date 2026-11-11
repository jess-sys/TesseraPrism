import SwiftUI
import PrismKit

extension EntryKind {
    var title: String {
        switch self {
        case .password: return "Passwords"
        case .totp: return "One-time codes"
        case .passkey: return "Passkeys"
        case .sshKey: return "SSH keys"
        case .recoveryCodes: return "Recovery codes"
        }
    }
    var icon: String {
        switch self {
        case .password: return "key.fill"
        case .totp: return "clock.badge.checkmark"
        case .passkey: return "person.badge.key.fill"
        case .sshKey: return "terminal"
        case .recoveryCodes: return "list.number"
        }
    }
}

struct EntryListView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var showAdd = false

    var filtered: [EntrySummary] {
        guard !query.isEmpty else { return model.entries }
        return model.entries.filter {
            $0.title.localizedCaseInsensitiveContains(query) || $0.subtitle.localizedCaseInsensitiveContains(query)
                || ($0.url?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(EntryKind.allCases, id: \.self) { kind in
                    let items = filtered.filter { $0.kind == kind }
                    if !items.isEmpty {
                        Section(kind.title) {
                            ForEach(items) { e in
                                NavigationLink(value: e) {
                                    Label {
                                        VStack(alignment: .leading) {
                                            Text(e.title)
                                            Text(e.subtitle).font(.caption).foregroundStyle(.secondary)
                                        }
                                    } icon: { Image(systemName: kind.icon) }
                                }
                            }
                        }
                    }
                }
            }
            .searchable(text: $query)
            .navigationTitle("Vault")
            .navigationDestination(for: EntrySummary.self) { EntryDetailView(summary: $0) }
            .toolbar {
                ToolbarItem { Button { showAdd = true } label: { Label("Add", systemImage: "plus") } }
                ToolbarItem { Button { Task { await model.refreshAll() } } label: { Label("Refresh", systemImage: "arrow.clockwise") } }
            }
            .sheet(isPresented: $showAdd) { AddEntryView() }
            .refreshable { await model.refreshAll() }
            .overlay { if model.entries.isEmpty { ContentUnavailableView("No entries", systemImage: "key", description: Text("Add a password or one-time code.")) } }
        }
    }
}

extension EntrySummary: Hashable {
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

struct EntryDetailView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let summary: EntrySummary
    @State private var secret: String?
    @State private var totp: (code: String, validUntil: UInt64)?
    @State private var confirmDelete = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Title", value: summary.title)
                if !summary.subtitle.isEmpty { LabeledContent("Account", value: summary.subtitle) }
                if let url = summary.url { LabeledContent("Website", value: url) }
                LabeledContent("Approval", value: summary.policy.rawValue)
            }
            switch summary.kind {
            case .password:
                Section("Password") {
                    if let secret {
                        Text(secret).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        Button("Copy") { Clipboard.copy(secret) }
                    } else {
                        Button("Reveal (approve on device)") { Task { secret = await model.reveal(summary.id, field: .password) } }
                    }
                    Button("Copy username") { Clipboard.copy(summary.subtitle) }
                }
                if summary.hasTotp { totpSection }
            case .totp: totpSection
            case .recoveryCodes:
                Section("Codes") {
                    if let secret { Text(secret).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                    else { Button("Reveal (approve on device)") { Task { secret = await model.reveal(summary.id, field: .recoveryCodes) } } }
                }
            case .sshKey:
                if let k = model.sshKeys.first(where: { $0.id == summary.id }) {
                    Section("Public key") {
                        Text(k.openssh).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button("Copy OpenSSH public key") { Clipboard.copy(k.openssh) }
                    }
                }
            case .passkey:
                Section { Text("Passkeys are used through AutoFill and USB/BLE FIDO.").foregroundStyle(.secondary) }
            }
            Section {
                Button("Delete from device", role: .destructive) { confirmDelete = true }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(summary.title)
        .confirmationDialog("Delete this entry? You must tap on the device to confirm.", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { Task { await model.delete(summary.id); dismiss() } }
        }
    }

    @ViewBuilder var totpSection: some View {
        Section("One-time code") {
            if let totp {
                Text(totp.code).font(.system(size: 34, weight: .bold, design: .monospaced))
                Text("Valid until \(Date(timeIntervalSince1970: TimeInterval(totp.validUntil)).formatted(date: .omitted, time: .standard))")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Copy") { Clipboard.copy(totp.code) }
            }
            Button(totp == nil ? "Get code (approve on device)" : "New code") { Task { totp = await model.totp(summary.id) } }
        }
    }
}

// MARK: - Add

struct AddEntryView: View {
    enum Kind: String, CaseIterable { case password = "Password", totp = "One-time code" }
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var kind: Kind = .password
    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var url = ""
    @State private var notes = ""
    @State private var otpauth = ""
    @State private var policy: ApprovalPolicy = .always
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Form {
                Picker("Type", selection: $kind) { ForEach(Kind.allCases, id: \.self) { Text($0.rawValue) } }.pickerStyle(.segmented)
                TextField("Title", text: $title)
                switch kind {
                case .password:
                    TextField("Username", text: $username)
                    SecureField("Password", text: $password)
                    Button("Generate password") { password = Self.generate() }
                    TextField("Website (https://...)", text: $url)
                    TextField("Notes", text: $notes)
                case .totp:
                    TextField("otpauth:// URI", text: $otpauth)
                    #if os(iOS)
                    Button("Scan QR code") { scanning = true }
                    #endif
                }
                Picker("Approval", selection: $policy) { ForEach(ApprovalPolicy.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
            }
            .formStyle(.grouped)
            .navigationTitle("Add entry")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Save") { Task { await save() } }.disabled(!valid) }
            }
            #if os(iOS)
            .sheet(isPresented: $scanning) {
                QRScannerView { code in otpauth = code; scanning = false; if title.isEmpty, let t = model.parseTotp(uri: code) { title = t.issuer.isEmpty ? t.account : t.issuer } }
            }
            #endif
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 420)
        #endif
    }

    var valid: Bool {
        !title.isEmpty && (kind == .password ? !password.isEmpty : otpauth.hasPrefix("otpauth://"))
    }

    func save() async {
        let now = UInt64(Date().timeIntervalSince1970)
        let data: EntryData
        switch kind {
        case .password:
            data = .password(Password(username: username, password: password, url: url.isEmpty ? nil : url, notes: notes))
        case .totp:
            guard let t = model.parseTotp(uri: otpauth) else { return }
            data = .totp(t)
        }
        let e = Entry(id: Entry.randomId(), title: title, created: now, modified: now, policy: policy, data: data)
        if await model.add(e) { dismiss() }
    }

    static func generate(length: Int = 24) -> String {
        let chars = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+")
        var g = SystemRandomNumberGenerator()
        return String((0..<length).map { _ in chars.randomElement(using: &g)! })
    }
}
