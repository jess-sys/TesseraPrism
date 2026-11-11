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

    // MARK: view setup

    #if os(iOS)
    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ProviderView(model: ui))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        wireCancel()
    }
    #else
    override func loadView() {
        let host = NSHostingView(rootView: ProviderView(model: ui))
        host.frame = NSRect(x: 0, y: 0, width: 360, height: 320)
        view = host
        preferredContentSize = NSSize(width: 360, height: 320)
        wireCancel()
    }
    #endif

    private func wireCancel() {
        ui.onCancel = { [weak self] in self?.cancel(.userCanceled) }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        work?.cancel()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    private func fail(_ error: Error) {
        ui.busy = false
        ui.error = error.localizedDescription
        // Leave the message visible; user dismisses with Cancel.
    }

    private func start(_ body: @escaping @MainActor (PrismClient) async throws -> Void) {
        ui.busy = true; ui.error = nil; ui.status = "Connecting to Prism..."
        work = Task { @MainActor in
            let (client, _, store) = PrismConnection.makeClient(scanTimeout: 10)
            do {
                _ = try await client.connect(needsPairing: !store.isPaired, syncTime: false) { [weak self] sas in
                    Task { @MainActor in self?.ui.sas = sas }
                }
                store.isPaired = true
                ui.sas = nil
                ui.status = "Approve on your Prism..."
                try await body(client)
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
        start { [weak self] client in
            guard let self else { return }
            let all = try await client.listEntries(kind: .password)
            let matches = all.filter { Self.matches($0, hosts: hosts) }
            let list = matches.isEmpty ? all : matches
            self.ui.busy = false
            self.ui.choices = list
            if list.isEmpty { self.ui.status = "No passwords on this Prism." }
            self.ui.onPick = { [weak self] summary in
                guard let self else { return }
                self.ui.choices = []; self.ui.busy = true; self.ui.status = "Approve on your Prism..."
                self.work = Task { @MainActor in
                    do {
                        let secret = try await client.getSecret(id: summary.id, field: .password, context: hosts.first)
                        guard let pw = secret.text else { throw PrismError.protocolViolation("empty secret") }
                        await client.disconnect()
                        _ = await self.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: summary.subtitle, password: pw))
                    } catch { self.fail(error) }
                }
            }
            // Keep the connection open for the pick; start() would disconnect on return, so park here.
            try await Self.waitUntilCancelled()
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
                self.ui.choices = []; self.ui.busy = true; self.ui.status = "Approve on your Prism..."
                self.work = Task { @MainActor in
                    do {
                        let t = try await client.getTotp(id: summary.id)
                        await client.disconnect()
                        _ = await self.extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: t.code))
                    } catch { self.fail(error) }
                }
            }
            try await Self.waitUntilCancelled()
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

    /// Keeps the BLE connection alive while the user picks from the list.
    private static func waitUntilCancelled() async throws {
        try await Task.sleep(nanoseconds: 120 * 1_000_000_000)
    }
}
