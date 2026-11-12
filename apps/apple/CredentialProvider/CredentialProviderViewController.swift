import AuthenticationServices
import os

private let extLog = Logger(subsystem: "ch.neutheria.prism", category: "extension")
import SwiftUI
import PrismKit

#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// AutoFill credential provider talking to the Prism device over BLE.
///
/// Flow for every request: show the sheet, connect (cached peripheral id => fast reconnect), run the
/// operation (the device asks for a tap), complete or cancel. Extensions are short-lived, so each
/// request opens and closes its own connection (see README "BLE inside an AutoFill extension").
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let ui = ProviderModel()
    private var work: Task<Void, Never>?
    private let cache = PasswordCacheStore()

    // MARK: view setup

    #if os(iOS)
    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ProviderView(model: ui).prismBranded())
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        wireCancel()
    }

    /// The sheet went away (completed, cancelled, or dismissed by the system): drop any work and
    /// its BLE session so it can't block other Prism processes.
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        work?.cancel(); watchdog?.cancel()
    }
    #else
    override func loadView() {
        let host = NSHostingView(rootView: ProviderView(model: ui).prismBranded())
        host.frame = NSRect(x: 0, y: 0, width: 360, height: 320)
        view = host
        preferredContentSize = NSSize(width: 360, height: 320)
        wireCancel()
    }

    /// Escape anywhere in the sheet cancels the request (AppKit sends cancelOperation: up the
    /// responder chain), so a stuck request never blocks the browser.
    override func cancelOperation(_ sender: Any?) {
        cancel(.userCanceled)
    }

    /// Escape cancels. The SwiftUI view inside the browser's sheet never becomes first
    /// responder, so watch key-downs for the whole extension process instead.
    private var escapeMonitor: Any?

    override func viewDidAppear() {
        super.viewDidAppear()
        view.window?.makeFirstResponder(view)
        if escapeMonitor == nil {
            escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                guard event.keyCode == 53 else { return event } // kVK_Escape
                self?.cancel(.userCanceled)
                return nil
            }
        }
    }

    /// The sheet went away (completed, cancelled, or dismissed by the system): drop any work and
    /// its BLE session so it can't block other Prism processes.
    override func viewDidDisappear() {
        super.viewDidDisappear()
        work?.cancel(); watchdog?.cancel()
        if let m = escapeMonitor { NSEvent.removeMonitor(m); escapeMonitor = nil }
    }
    #endif

    /// Never leave a request (and its BLE session) hanging: give up after 2 minutes.
    private var watchdog: Task<Void, Never>?
    private func armWatchdog() {
        watchdog?.cancel()
        watchdog = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 120_000_000_000)
            guard !Task.isCancelled, let self else { return }
            extLog.notice("request watchdog fired")
            self.cancel(.userCanceled)
        }
    }

    private func wireCancel() {
        ui.onCancel = { [weak self] in self?.cancel(.userCanceled) }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        work?.cancel()
        watchdog?.cancel()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    private func fail(_ error: Error) {
        ui.busy = false
        ui.error = error.localizedDescription
        ui.activity = .failure(error.localizedDescription)
        // Leave the message visible; user dismisses with Cancel.
    }

    private func start(_ body: @escaping @MainActor (PrismClient) async throws -> Void) {
        ui.busy = true; ui.error = nil; ui.status = "Connecting to Prism..."; ui.activity = .searching
        work?.cancel()
        armWatchdog()
        work = Task { @MainActor in
            let (client, _, store) = PrismConnection.makeClient(scanTimeout: 10)
            do {
                _ = try await client.connect(needsPairing: !store.isPaired, syncTime: false) { [weak self] sas in
                    Task { @MainActor in self?.ui.sas = sas; self?.ui.activity = .pairing(code: sas) }
                }
                store.isPaired = true
                ui.sas = nil
                ui.status = "Approve on your Prism..."; ui.activity = .approve
                // In standby the device wakes to its PIN pad: wait for the user to unlock it.
                try await untilUnlocked(onLocked: { [weak self] in
                    self?.ui.status = "Unlock your Tessera Prism to continue..."; self?.ui.activity = .unlock
                }) {
                    try await body(client)
                }
            } catch is CancellationError {
                extLog.notice("request cancelled")
            } catch {
                extLog.error("request failed: \(String(describing: error), privacy: .public)")
                fail(error)
            }
            await client.disconnect()
        }
    }

    // MARK: passwords

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let hosts = Self.hosts(from: serviceIdentifiers)
        // A valid local cache lists without contacting the Prism; the password needs biometrics.
        if let meta = cache.metadata(), !meta.entries.isEmpty {
            let all = meta.entries.map { EntrySummary(id: $0.id, kind: .password, title: $0.title, subtitle: $0.username, url: $0.url) }
            let matches = all.filter { Self.matches($0, hosts: hosts) }
            ui.busy = false
            ui.choices = matches.isEmpty ? all : matches
            ui.onPick = { [weak self] summary in
                guard let self else { return }
                self.ui.choices = []; self.ui.busy = true
                self.fillFromCache(id: summary.id, title: summary.title, user: summary.subtitle, host: hosts.first)
            }
            return
        }
        start { [weak self] client in
            guard let self else { return }
            let all = try await client.listEntries(kind: .password)
            let matches = all.filter { Self.matches($0, hosts: hosts) }
            let list = matches.isEmpty ? all : matches
            self.ui.busy = false
            self.ui.choices = list
            if list.isEmpty { self.ui.status = "No passwords on this Prism." }
            // Don't hold the session while the user picks: a parked session blocks every other
            // Prism process on the shared link if the sheet goes away without telling us.
            // start() disconnects when this returns; the pick reconnects.
            self.ui.onPick = { [weak self] summary in
                guard let self else { return }
                self.ui.choices = []
                self.deviceFill(id: summary.id, host: hosts.first ?? summary.title, user: summary.subtitle)
            }
        }
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        // The device always needs a physical tap, so we can never answer silently.
        cancel(.userInteractionRequired)
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        cancel(.userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        switch credentialRequest.type {
        case .password:
            guard let req = credentialRequest as? ASPasswordCredentialRequest else { return cancel(.failed) }
            providePassword(req)
        case .passkeyAssertion:
            guard let req = credentialRequest as? ASPasskeyCredentialRequest else { return cancel(.failed) }
            guard let id = req.credentialIdentity as? ASPasskeyCredentialIdentity else { return cancel(.failed) }
            provideAssertion(rpId: id.relyingPartyIdentifier, clientDataHash: req.clientDataHash,
                             allowed: [id.credentialID], fallbackUserHandle: id.userHandle,
                             uv: req.userVerificationPreference != .discouraged)
        default:
            if #available(iOS 18.0, macOS 15.0, *), credentialRequest.type == .oneTimeCode,
               let req = credentialRequest as? ASOneTimeCodeCredentialRequest {
                provideOneTimeCode(recordIdentifier: req.credentialIdentity.recordIdentifier)
            } else {
                cancel(.failed)
            }
        }
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        providePassword(recordIdentifier: credentialIdentity.recordIdentifier, host: credentialIdentity.serviceIdentifier.identifier,
                        user: credentialIdentity.user)
    }

    private func providePassword(_ req: ASPasswordCredentialRequest) {
        providePassword(recordIdentifier: req.credentialIdentity.recordIdentifier, host: req.credentialIdentity.serviceIdentifier.identifier,
                        user: req.credentialIdentity.user)
    }

    private func providePassword(recordIdentifier: String?, host: String, user: String) {
        guard let rid = recordIdentifier, let id = EntryId(hex: rid) else { return cancel(.credentialIdentityNotFound) }
        if let meta = cache.metadata(), let e = meta.entries.first(where: { $0.id == id }) {
            ui.busy = true
            fillFromCache(id: id, title: e.title, user: user, host: host)
            return
        }
        deviceFill(id: id, host: host, user: user)
    }

    /// Decrypts the cached password after biometric unlock of the key; any failure falls back to the device.
    private func fillFromCache(id: EntryId, title: String, user: String, host: String?) {
        let cache = self.cache
        let site = host ?? title
        work = Task { @MainActor in
            let result = await Task.detached { Result { try cache.password(id: id, reason: "Fill password for \(site)") } }.value
            if case .success(let pw?) = result {
                _ = await self.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: pw))
                return
            }
            extLog.notice("cache miss/failed, using the device: \(String(describing: result), privacy: .public)")
            self.deviceFill(id: id, host: host ?? title, user: user)
        }
    }

    private func deviceFill(id: EntryId, host: String, user: String) {
        start { [weak self] client in
            let secret = try await client.getSecret(id: id, field: .password, context: host)
            guard let pw = secret.text else { throw PrismError.protocolViolation("empty secret") }
            await client.disconnect()
            _ = await self?.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: pw))
        }
    }

    // MARK: passkeys

    @available(iOS 17.0, macOS 14.0, *)
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        provideAssertion(rpId: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
                         allowed: requestParameters.allowedCredentials, fallbackUserHandle: nil,
                         uv: requestParameters.userVerificationPreference != .discouraged)
    }

    private func provideAssertion(rpId: String, clientDataHash: Data, allowed: [Data], fallbackUserHandle: Data?, uv: Bool) {
        start { [weak self] client in
            let allow = allowed.filter { !$0.isEmpty }.map { [UInt8]($0) }
            let cbor = CTAP.getAssertionRequest(rpId: rpId, clientDataHash: [UInt8](clientDataHash), allowCredentialIds: allow, userVerification: uv)
            let resp = try await client.ctap(cbor: cbor, originHint: rpId)
            let a = try CTAP.parseAssertion(resp, fallbackCredentialId: allow.first ?? [])
            await client.disconnect()
            let cred = ASPasskeyAssertionCredential(
                userHandle: a.userHandle.map { Data($0) } ?? fallbackUserHandle ?? Data(),
                relyingParty: rpId, signature: Data(a.signature), clientDataHash: clientDataHash,
                authenticatorData: Data(a.authenticatorData), credentialID: Data(a.credentialId))
            _ = await self?.extensionContext.completeAssertionRequest(using: cred)
        }
    }

    @available(iOS 17.0, macOS 14.0, *)
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let req = registrationRequest as? ASPasskeyCredentialRequest,
              let id = req.credentialIdentity as? ASPasskeyCredentialIdentity else { return cancel(.failed) }
        let supported = req.supportedAlgorithms.map { Int64($0.rawValue) }.filter { $0 == -7 || $0 == -8 }
        start { [weak self] client in
            let cbor = CTAP.makeCredentialRequest(
                rpId: id.relyingPartyIdentifier, rpName: id.relyingPartyIdentifier,
                clientDataHash: [UInt8](req.clientDataHash), userId: [UInt8](id.userHandle),
                userName: id.userName, userDisplayName: id.userName,
                algorithms: supported.isEmpty ? [-7] : supported)
            extLog.notice("register: rp=\(id.relyingPartyIdentifier, privacy: .public) algs=\(supported, privacy: .public)")
            let resp = try await client.ctap(cbor: cbor, originHint: id.relyingPartyIdentifier)
            extLog.notice("register: ctap status=\(resp.first ?? 0xff, privacy: .public) len=\(resp.count, privacy: .public)")
            let r = try CTAP.parseRegistration(resp)
            await client.disconnect()
            let hex = { (b: [UInt8]) in b.map { String(format: "%02x", $0) }.joined() }
            extLog.notice("register: credId=\(hex(r.credentialId), privacy: .public) authData flags=\(String(format: "%02x", r.authenticatorData.count > 32 ? r.authenticatorData[32] : 0), privacy: .public)")
            extLog.debug("register: attestationObject=\(hex(r.attestationObject), privacy: .public)")
            // Tell the system the Prism holds this passkey, so browsers that check the identity
            // store first (Chrome) offer it at sign-in. Done before completing: the extension may
            // be torn down right after.
            let store = ASCredentialIdentityStore.shared
            if await store.state().isEnabled {
                try? await store.saveCredentialIdentities([ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: id.relyingPartyIdentifier, userName: id.userName,
                    credentialID: Data(r.credentialId), userHandle: id.userHandle, recordIdentifier: nil)])
            }
            let cred = ASPasskeyRegistrationCredential(
                relyingParty: id.relyingPartyIdentifier, clientDataHash: req.clientDataHash,
                credentialID: Data(r.credentialId), attestationObject: Data(r.attestationObject))
            let accepted = await self?.extensionContext.completeRegistrationRequest(using: cred)
            extLog.notice("register: completeRegistrationRequest accepted=\(String(describing: accepted), privacy: .public)")
        }
    }

    // MARK: one-time codes (iOS 18 / macOS 15)

    @available(iOS 18.0, macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let hosts = Self.hosts(from: serviceIdentifiers)
        start { [weak self] client in
            guard let self else { return }
            let all = try await client.listEntries().filter { $0.kind == .totp || $0.hasTotp }
            let matches = all.filter { Self.matches($0, hosts: hosts) }
            let list = matches.isEmpty ? all : matches
            self.ui.busy = false; self.ui.choices = list
            if list.isEmpty { self.ui.status = "No one-time codes on this Prism." }
            self.ui.onPick = { [weak self] summary in
                guard let self else { return }
                self.ui.choices = []
                self.provideOneTimeCode(recordIdentifier: summary.id.hex)
            }
        }
    }

    @available(iOS 18.0, macOS 15.0, *)
    private func provideOneTimeCode(recordIdentifier: String?) {
        guard let rid = recordIdentifier, let id = EntryId(hex: rid) else { return cancel(.credentialIdentityNotFound) }
        start { [weak self] client in
            let t = try await client.getTotp(id: id)
            await client.disconnect()
            _ = await self?.extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: t.code))
        }
    }

    // MARK: helpers

    private static func hosts(from ids: [ASCredentialServiceIdentifier]) -> [String] {
        ids.map { id in
            switch id.type {
            case .URL: return URL(string: id.identifier)?.host ?? id.identifier
            default: return id.identifier
            }
        }
    }

    private static func matches(_ e: EntrySummary, hosts: [String]) -> Bool {
        guard let url = e.url?.lowercased(), !hosts.isEmpty else { return false }
        let eh = URL(string: url)?.host ?? url
        return hosts.contains { h in
            let h = h.lowercased()
            return eh == h || eh.hasSuffix("." + h) || h.hasSuffix("." + eh)
        }
    }
}
