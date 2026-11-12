import Foundation

// Codable mirror of crates/prism-core/src/model.rs and the Request/Response enums of
// ARCHITECTURE.md §5.3. The JSON shapes match serde_json's default encodings:
//  - structs -> objects with snake_case keys, `Option::None` -> null
//  - unit enum variants -> "Variant"; data variants -> {"Variant": payload}
//  - byte arrays / Vec<u8> / [u8;N] -> arrays of numbers (so we use [UInt8], never Data)
//  - newtype structs (EntryId) are transparent

// MARK: - Helpers

struct AnyKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init(_ s: String) { stringValue = s }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Decodes a serde externally-tagged enum: returns (tag, container-for-payload) or unit tag.
enum Tagged {
    case unit(String)
    case data(String, KeyedDecodingContainer<AnyKey>)

    static func read(_ decoder: Decoder) throws -> Tagged {
        if let single = try? decoder.singleValueContainer(), let s = try? single.decode(String.self) {
            return .unit(s)
        }
        let c = try decoder.container(keyedBy: AnyKey.self)
        guard c.allKeys.count == 1, let k = c.allKeys.first else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "expected single-key enum object"))
        }
        return .data(k.stringValue, c)
    }
}

private func unknownVariant(_ tag: String, _ type: String) -> DecodingError {
    DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "unknown \(type) variant \(tag)"))
}

/// Encode a unit-only enum as a bare string.
private func encodeUnit(_ s: String, _ encoder: Encoder) throws {
    var c = encoder.singleValueContainer()
    try c.encode(s)
}

/// Defines a string-raw unit-variant enum with serde-compatible coding.
public protocol SerdeUnitEnum: RawRepresentable, Codable, Hashable, Sendable where RawValue == String {}
public extension SerdeUnitEnum {
    init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        guard let v = Self(rawValue: s) else { throw unknownVariant(s, String(describing: Self.self)) }
        self = v
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
}

/// Arbitrary JSON (used for opaque payloads such as ProtoError).
public enum JSONValue: Codable, Equatable, Sendable {
    case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

// MARK: - Entry id

/// 16-byte entry id; serializes transparently as `[n, ...]`.
public struct EntryId: Codable, Hashable, Sendable {
    public var bytes: [UInt8]
    public init(bytes: [UInt8]) { self.bytes = bytes }
    public init(from decoder: Decoder) throws {
        bytes = try decoder.singleValueContainer().decode([UInt8].self)
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(bytes)
    }
    public var hex: String { bytes.map { String(format: "%02x", $0) }.joined() }
    public init?(hex: String) {
        guard hex.count == 32 else { return nil }
        var out: [UInt8] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        self.init(bytes: out)
    }
}

// MARK: - Unit enums

public enum EntryKind: String, SerdeUnitEnum, CaseIterable {
    case password = "Password", totp = "Totp", passkey = "Passkey", sshKey = "SshKey", recoveryCodes = "RecoveryCodes"
}
public enum ApprovalPolicy: String, SerdeUnitEnum, CaseIterable {
    case always = "Always", session = "Session", never = "Never"
    /// Follow the device-wide default for the operation (`DeviceSettings.approvals`).
    case `default` = "Default"
}
public enum ApprovalOp: String, SerdeUnitEnum, CaseIterable {
    case password = "Password", totp = "Totp", sshSign = "SshSign", passkey = "Passkey"
    case recoveryCodes = "RecoveryCodes", typeOverUsb = "TypeOverUsb", modify = "Modify", delete = "Delete"
}

public struct ApprovalDefaults: Codable, Equatable, Sendable {
    public var password: ApprovalPolicy
    public var totp: ApprovalPolicy
    public var sshSign: ApprovalPolicy
    public var passkey: ApprovalPolicy
    public var recoveryCodes: ApprovalPolicy
    public var typeOverUsb: ApprovalPolicy
    public var modify: ApprovalPolicy
    public var delete: ApprovalPolicy
    enum CodingKeys: String, CodingKey {
        case password, totp, sshSign = "ssh_sign", passkey, recoveryCodes = "recovery_codes"
        case typeOverUsb = "type_over_usb", modify, delete
    }
    public init(password: ApprovalPolicy = .always, totp: ApprovalPolicy = .always, sshSign: ApprovalPolicy = .always,
                passkey: ApprovalPolicy = .always, recoveryCodes: ApprovalPolicy = .always,
                typeOverUsb: ApprovalPolicy = .always, modify: ApprovalPolicy = .always, delete: ApprovalPolicy = .always) {
        self.password = password; self.totp = totp; self.sshSign = sshSign; self.passkey = passkey
        self.recoveryCodes = recoveryCodes; self.typeOverUsb = typeOverUsb; self.modify = modify; self.delete = delete
    }
    public subscript(op: ApprovalOp) -> ApprovalPolicy {
        get {
            switch op {
            case .password: return password
            case .totp: return totp
            case .sshSign: return sshSign
            case .passkey: return passkey
            case .recoveryCodes: return recoveryCodes
            case .typeOverUsb: return typeOverUsb
            case .modify: return modify
            case .delete: return delete
            }
        }
        set {
            switch op {
            case .password: password = newValue
            case .totp: totp = newValue
            case .sshSign: sshSign = newValue
            case .passkey: passkey = newValue
            case .recoveryCodes: recoveryCodes = newValue
            case .typeOverUsb: typeOverUsb = newValue
            case .modify: modify = newValue
            case .delete: delete = newValue
            }
        }
    }
}
public enum TotpAlgorithm: String, SerdeUnitEnum { case sha1 = "Sha1", sha256 = "Sha256", sha512 = "Sha512" }
public enum CoseAlg: String, SerdeUnitEnum { case es256 = "Es256", edDsa = "EdDsa" }
public enum SecretField: String, SerdeUnitEnum {
    case password = "Password", username = "Username", notes = "Notes", totpSecret = "TotpSecret"
    case recoveryCodes = "RecoveryCodes", sshPublicKey = "SshPublicKey"
}
public enum KeyboardLayout: String, SerdeUnitEnum, CaseIterable { case us = "Us", frAzerty = "FrAzerty" }
public enum SleepMode: String, SerdeUnitEnum, CaseIterable { case powerOff = "PowerOff", lightSleep = "LightSleep" }
public enum Orientation: String, SerdeUnitEnum, CaseIterable { case portrait = "Portrait", landscape = "Landscape" }
public enum ImportMode: String, SerdeUnitEnum, CaseIterable { case replace = "Replace", merge = "Merge" }
public enum ErrorCode: String, SerdeUnitEnum {
    case locked = "Locked", denied = "Denied", timeout = "Timeout", notFound = "NotFound", notPaired = "NotPaired"
    case invalidRequest = "InvalidRequest", badPassphrase = "BadPassphrase", storageFull = "StorageFull"
    case unsupported = "Unsupported", busy = "Busy", `internal` = "Internal"
}

// MARK: - Structs

public struct Totp: Codable, Equatable, Sendable {
    public var issuer: String
    public var account: String
    public var secret: [UInt8]
    public var algorithm: TotpAlgorithm
    public var digits: UInt8
    public var period: UInt32
    public init(issuer: String, account: String, secret: [UInt8], algorithm: TotpAlgorithm = .sha1, digits: UInt8 = 6, period: UInt32 = 30) {
        self.issuer = issuer; self.account = account; self.secret = secret
        self.algorithm = algorithm; self.digits = digits; self.period = period
    }
}

public struct Password: Codable, Equatable, Sendable {
    public var username: String
    public var password: String
    public var url: String?
    public var notes: String
    public var totp: Totp?
    public init(username: String, password: String, url: String? = nil, notes: String = "", totp: Totp? = nil) {
        self.username = username; self.password = password; self.url = url; self.notes = notes; self.totp = totp
    }
    enum CodingKeys: String, CodingKey { case username, password, url, notes, totp }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username); try c.encode(password, forKey: .password)
        try c.encode(url, forKey: .url); try c.encode(notes, forKey: .notes); try c.encode(totp, forKey: .totp)
    }
}

public struct Passkey: Codable, Equatable, Sendable {
    public var rpId: String
    public var rpName: String
    public var userHandle: [UInt8]
    public var userName: String
    public var userDisplayName: String
    public var credentialId: [UInt8]
    public var alg: CoseAlg
    public var keyNonce: [UInt8]
    public var created: UInt64
    enum CodingKeys: String, CodingKey {
        case rpId = "rp_id", rpName = "rp_name", userHandle = "user_handle", userName = "user_name"
        case userDisplayName = "user_display_name", credentialId = "credential_id", alg
        case keyNonce = "key_nonce", created
    }
}

public enum SshKeySource: Codable, Equatable, Sendable {
    case derived(index: UInt32)
    case imported(secret: [UInt8])
    public init(from decoder: Decoder) throws {
        guard case .data(let tag, let c) = try Tagged.read(decoder) else { throw unknownVariant("unit", "SshKeySource") }
        let inner = try c.nestedContainer(keyedBy: AnyKey.self, forKey: AnyKey(tag))
        switch tag {
        case "Derived": self = .derived(index: try inner.decode(UInt32.self, forKey: AnyKey("index")))
        case "Imported": self = .imported(secret: try inner.decode([UInt8].self, forKey: AnyKey("secret")))
        default: throw unknownVariant(tag, "SshKeySource")
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyKey.self)
        switch self {
        case .derived(let i):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: AnyKey("Derived"))
            try n.encode(i, forKey: AnyKey("index"))
        case .imported(let s):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: AnyKey("Imported"))
            try n.encode(s, forKey: AnyKey("secret"))
        }
    }
}

public struct SshKey: Codable, Equatable, Sendable {
    public var comment: String
    public var source: SshKeySource
    public var publicKey: [UInt8]
    enum CodingKeys: String, CodingKey { case comment, source, publicKey = "public_key" }
}

public struct RecoveryCode: Codable, Equatable, Sendable {
    public var code: String
    public var used: Bool
    public init(code: String, used: Bool = false) { self.code = code; self.used = used }
}

public struct RecoveryCodes: Codable, Equatable, Sendable {
    public var service: String
    public var codes: [RecoveryCode]
    public var notes: String
    public init(service: String, codes: [RecoveryCode], notes: String = "") { self.service = service; self.codes = codes; self.notes = notes }
}

public enum EntryData: Codable, Equatable, Sendable {
    case password(Password)
    case totp(Totp)
    case passkey(Passkey)
    case sshKey(SshKey)
    case recoveryCodes(RecoveryCodes)

    public init(from decoder: Decoder) throws {
        guard case .data(let tag, let c) = try Tagged.read(decoder) else { throw unknownVariant("unit", "EntryData") }
        let k = AnyKey(tag)
        switch tag {
        case "Password": self = .password(try c.decode(Password.self, forKey: k))
        case "Totp": self = .totp(try c.decode(Totp.self, forKey: k))
        case "Passkey": self = .passkey(try c.decode(Passkey.self, forKey: k))
        case "SshKey": self = .sshKey(try c.decode(SshKey.self, forKey: k))
        case "RecoveryCodes": self = .recoveryCodes(try c.decode(RecoveryCodes.self, forKey: k))
        default: throw unknownVariant(tag, "EntryData")
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyKey.self)
        switch self {
        case .password(let v): try c.encode(v, forKey: AnyKey("Password"))
        case .totp(let v): try c.encode(v, forKey: AnyKey("Totp"))
        case .passkey(let v): try c.encode(v, forKey: AnyKey("Passkey"))
        case .sshKey(let v): try c.encode(v, forKey: AnyKey("SshKey"))
        case .recoveryCodes(let v): try c.encode(v, forKey: AnyKey("RecoveryCodes"))
        }
    }
}

public struct Entry: Codable, Equatable, Sendable {
    public var id: EntryId
    public var title: String
    public var tags: [String]
    public var created: UInt64
    public var modified: UInt64
    public var policy: ApprovalPolicy
    public var data: EntryData
    public init(id: EntryId, title: String, tags: [String] = [], created: UInt64, modified: UInt64,
                policy: ApprovalPolicy = .default, data: EntryData) {
        self.id = id; self.title = title; self.tags = tags; self.created = created
        self.modified = modified; self.policy = policy; self.data = data
    }
    public static func randomId() -> EntryId {
        EntryId(bytes: (0..<16).map { _ in UInt8.random(in: 0...255) })
    }
}

/// Public identifiers of a passkey stored on the device (no key material), used to register it
/// with the system credential store so browsers know the Prism can answer for the site.
public struct PasskeyIdentity: Codable, Equatable, Sendable {
    public var id: EntryId
    public var rpId: String
    public var userName: String
    public var userHandle: [UInt8]
    public var credentialId: [UInt8]
    enum CodingKeys: String, CodingKey { case id, rpId = "rp_id", userName = "user_name", userHandle = "user_handle", credentialId = "credential_id" }
    public init(id: EntryId, rpId: String, userName: String, userHandle: [UInt8], credentialId: [UInt8]) {
        self.id = id; self.rpId = rpId; self.userName = userName; self.userHandle = userHandle; self.credentialId = credentialId
    }
}

public struct EntrySummary: Codable, Equatable, Sendable, Identifiable {
    public var id: EntryId
    public var kind: EntryKind
    public var title: String
    public var subtitle: String
    public var url: String?
    public var tags: [String]
    public var modified: UInt64
    public var hasTotp: Bool
    public var policy: ApprovalPolicy
    enum CodingKeys: String, CodingKey { case id, kind, title, subtitle, url, tags, modified, hasTotp = "has_totp", policy }
    public init(id: EntryId, kind: EntryKind, title: String, subtitle: String, url: String? = nil, tags: [String] = [],
                modified: UInt64 = 0, hasTotp: Bool = false, policy: ApprovalPolicy = .always) {
        self.id = id; self.kind = kind; self.title = title; self.subtitle = subtitle; self.url = url
        self.tags = tags; self.modified = modified; self.hasTotp = hasTotp; self.policy = policy
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(kind, forKey: .kind); try c.encode(title, forKey: .title)
        try c.encode(subtitle, forKey: .subtitle); try c.encode(url, forKey: .url); try c.encode(tags, forKey: .tags)
        try c.encode(modified, forKey: .modified); try c.encode(hasTotp, forKey: .hasTotp); try c.encode(policy, forKey: .policy)
    }
}

public enum SecretValue: Codable, Equatable, Sendable {
    case text(String)
    case bytes([UInt8])
    case list([String])
    public init(from decoder: Decoder) throws {
        guard case .data(let tag, let c) = try Tagged.read(decoder) else { throw unknownVariant("unit", "SecretValue") }
        let k = AnyKey(tag)
        switch tag {
        case "Text": self = .text(try c.decode(String.self, forKey: k))
        case "Bytes": self = .bytes(try c.decode([UInt8].self, forKey: k))
        case "List": self = .list(try c.decode([String].self, forKey: k))
        default: throw unknownVariant(tag, "SecretValue")
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyKey.self)
        switch self {
        case .text(let v): try c.encode(v, forKey: AnyKey("Text"))
        case .bytes(let v): try c.encode(v, forKey: AnyKey("Bytes"))
        case .list(let v): try c.encode(v, forKey: AnyKey("List"))
        }
    }
    public var text: String? {
        switch self {
        case .text(let s): return s
        case .bytes(let b): return String(decoding: b, as: UTF8.self)
        case .list(let l): return l.joined(separator: "\n")
        }
    }
}

public struct SshPublicKey: Codable, Equatable, Sendable, Identifiable {
    public var id: EntryId
    public var name: String
    public var comment: String
    public var blob: [UInt8]
    public var openssh: String
}

public struct DeviceSettings: Codable, Equatable, Sendable {
    public var autoLockSecs: UInt32
    public var sleepMode: SleepMode
    public var keyboardLayout: KeyboardLayout
    public var orientation: Orientation
    public var buzzer: Bool
    public var ownerInfo: String?
    public var approvals: ApprovalDefaults
    /// Validity of the companion password cache in seconds; 0 = disabled.
    public var passwordCacheSecs: UInt32
    enum CodingKeys: String, CodingKey {
        case autoLockSecs = "auto_lock_secs", sleepMode = "sleep_mode", keyboardLayout = "keyboard_layout"
        case orientation, buzzer, ownerInfo = "owner_info", approvals, passwordCacheSecs = "password_cache_secs"
    }
    public init(autoLockSecs: UInt32 = 180, sleepMode: SleepMode = .powerOff, keyboardLayout: KeyboardLayout = .us,
                orientation: Orientation = .portrait, buzzer: Bool = true, ownerInfo: String? = nil,
                approvals: ApprovalDefaults = ApprovalDefaults(), passwordCacheSecs: UInt32 = 0) {
        self.approvals = approvals; self.passwordCacheSecs = passwordCacheSecs
        self.autoLockSecs = autoLockSecs; self.sleepMode = sleepMode; self.keyboardLayout = keyboardLayout
        self.orientation = orientation; self.buzzer = buzzer; self.ownerInfo = ownerInfo
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(autoLockSecs, forKey: .autoLockSecs); try c.encode(sleepMode, forKey: .sleepMode)
        try c.encode(keyboardLayout, forKey: .keyboardLayout); try c.encode(orientation, forKey: .orientation)
        try c.encode(buzzer, forKey: .buzzer); try c.encode(ownerInfo, forKey: .ownerInfo)
        try c.encode(approvals, forKey: .approvals); try c.encode(passwordCacheSecs, forKey: .passwordCacheSecs)
    }
}

public struct PairedHost: Codable, Equatable, Sendable, Identifiable {
    public var publicKey: [UInt8]
    public var label: String
    public var pairedAt: UInt64
    public var lastSeen: UInt64
    public var id: [UInt8] { publicKey }
    enum CodingKeys: String, CodingKey { case publicKey = "public_key", label, pairedAt = "paired_at", lastSeen = "last_seen" }
}

public struct DeviceInfo: Codable, Equatable, Sendable {
    public var fwVersion: String
    public var devicePubkey: [UInt8]
    public var locked: Bool
    public var initialized: Bool
    public var batteryPct: UInt8
    public var charging: Bool
    public var entryCount: UInt32
    public var timeValid: Bool
    enum CodingKeys: String, CodingKey {
        case fwVersion = "fw_version", devicePubkey = "device_pubkey", locked, initialized
        case batteryPct = "battery_pct", charging, entryCount = "entry_count", timeValid = "time_valid"
    }
}

// MARK: - Request

public enum Request: Codable, Equatable, Sendable {
    case getInfo
    case setTime(unix: UInt64)
    case unlock(passphrase: String)
    case lock
    case listEntries(kind: EntryKind?)
    case getSecret(id: EntryId, field: SecretField, context: String?)
    case getTotp(id: EntryId)
    case addEntry(entry: Entry)
    case updateEntry(entry: Entry)
    case deleteEntry(id: EntryId)
    case markRecoveryCodeUsed(id: EntryId, index: UInt16)
    case generateSshKey(name: String, comment: String, policy: ApprovalPolicy)
    case sshListKeys
    case sshSign(publicKey: [UInt8], data: [UInt8], flags: UInt32, hostHint: String?)
    case ctap(cbor: [UInt8], originHint: String?)
    case typeEntry(id: EntryId, field: SecretField, layout: KeyboardLayout)
    case export(passphrase: String)
    case setRecoveryPassphrase(passphrase: String)
    case getEntry(id: EntryId)
    case listPasskeys
    case exportChunk(offset: UInt32)
    case importBegin(totalLen: UInt32)
    case importChunk(offset: UInt32, data: [UInt8])
    case importCommit(passphrase: String, mode: ImportMode)
    case listPairedHosts
    case removePairedHost(publicKey: [UInt8])
    case renamePairedHost(publicKey: [UInt8], label: String)
    case getSettings
    case setSettings(settings: DeviceSettings)
    case setEntryPolicy(id: EntryId, policy: ApprovalPolicy)
    case passwordSnapshot

    public init(from decoder: Decoder) throws {
        switch try Tagged.read(decoder) {
        case .unit(let t):
            switch t {
            case "GetInfo": self = .getInfo
            case "Lock": self = .lock
            case "SshListKeys": self = .sshListKeys
            case "ListPairedHosts": self = .listPairedHosts
            case "GetSettings": self = .getSettings
            case "ListPasskeys": self = .listPasskeys
            case "PasswordSnapshot": self = .passwordSnapshot
            default: throw unknownVariant(t, "Request")
            }
        case .data(let t, let c):
            let n = try c.nestedContainer(keyedBy: AnyKey.self, forKey: AnyKey(t))
            func k(_ s: String) -> AnyKey { AnyKey(s) }
            switch t {
            case "SetTime": self = .setTime(unix: try n.decode(UInt64.self, forKey: k("unix")))
            case "Unlock": self = .unlock(passphrase: try n.decode(String.self, forKey: k("passphrase")))
            case "ListEntries": self = .listEntries(kind: try n.decodeIfPresent(EntryKind.self, forKey: k("kind")))
            case "GetSecret": self = .getSecret(id: try n.decode(EntryId.self, forKey: k("id")), field: try n.decode(SecretField.self, forKey: k("field")), context: try n.decodeIfPresent(String.self, forKey: k("context")))
            case "GetTotp": self = .getTotp(id: try n.decode(EntryId.self, forKey: k("id")))
            case "AddEntry": self = .addEntry(entry: try n.decode(Entry.self, forKey: k("entry")))
            case "UpdateEntry": self = .updateEntry(entry: try n.decode(Entry.self, forKey: k("entry")))
            case "DeleteEntry": self = .deleteEntry(id: try n.decode(EntryId.self, forKey: k("id")))
            case "MarkRecoveryCodeUsed": self = .markRecoveryCodeUsed(id: try n.decode(EntryId.self, forKey: k("id")), index: try n.decode(UInt16.self, forKey: k("index")))
            case "GenerateSshKey": self = .generateSshKey(name: try n.decode(String.self, forKey: k("name")), comment: try n.decode(String.self, forKey: k("comment")), policy: try n.decode(ApprovalPolicy.self, forKey: k("policy")))
            case "SshSign": self = .sshSign(publicKey: try n.decode([UInt8].self, forKey: k("public_key")), data: try n.decode([UInt8].self, forKey: k("data")), flags: try n.decode(UInt32.self, forKey: k("flags")), hostHint: try n.decodeIfPresent(String.self, forKey: k("host_hint")))
            case "Ctap": self = .ctap(cbor: try n.decode([UInt8].self, forKey: k("cbor")), originHint: try n.decodeIfPresent(String.self, forKey: k("origin_hint")))
            case "TypeEntry": self = .typeEntry(id: try n.decode(EntryId.self, forKey: k("id")), field: try n.decode(SecretField.self, forKey: k("field")), layout: try n.decode(KeyboardLayout.self, forKey: k("layout")))
            case "Export": self = .export(passphrase: try n.decode(String.self, forKey: k("passphrase")))
            case "SetRecoveryPassphrase": self = .setRecoveryPassphrase(passphrase: try n.decode(String.self, forKey: k("passphrase")))
            case "GetEntry": self = .getEntry(id: try n.decode(EntryId.self, forKey: k("id")))
            case "ExportChunk": self = .exportChunk(offset: try n.decode(UInt32.self, forKey: k("offset")))
            case "ImportBegin": self = .importBegin(totalLen: try n.decode(UInt32.self, forKey: k("total_len")))
            case "ImportChunk": self = .importChunk(offset: try n.decode(UInt32.self, forKey: k("offset")), data: try n.decode([UInt8].self, forKey: k("data")))
            case "ImportCommit": self = .importCommit(passphrase: try n.decode(String.self, forKey: k("passphrase")), mode: try n.decode(ImportMode.self, forKey: k("mode")))
            case "RemovePairedHost": self = .removePairedHost(publicKey: try n.decode([UInt8].self, forKey: k("public_key")))
            case "RenamePairedHost": self = .renamePairedHost(publicKey: try n.decode([UInt8].self, forKey: k("public_key")), label: try n.decode(String.self, forKey: k("label")))
            case "SetSettings": self = .setSettings(settings: try n.decode(DeviceSettings.self, forKey: k("settings")))
            case "SetEntryPolicy": self = .setEntryPolicy(id: try n.decode(EntryId.self, forKey: k("id")), policy: try n.decode(ApprovalPolicy.self, forKey: k("policy")))
            default: throw unknownVariant(t, "Request")
            }
        }
    }

    public func encode(to encoder: Encoder) throws {
        func unit(_ s: String) throws { try encodeUnit(s, encoder) }
        func variant(_ tag: String, _ body: (inout KeyedEncodingContainer<AnyKey>) throws -> Void) throws {
            var c = encoder.container(keyedBy: AnyKey.self)
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: AnyKey(tag))
            try body(&n)
        }
        func k(_ s: String) -> AnyKey { AnyKey(s) }
        switch self {
        case .getInfo: try unit("GetInfo")
        case .lock: try unit("Lock")
        case .sshListKeys: try unit("SshListKeys")
        case .listPairedHosts: try unit("ListPairedHosts")
        case .getSettings: try unit("GetSettings")
        case .listPasskeys: try unit("ListPasskeys")
        case .passwordSnapshot: try unit("PasswordSnapshot")
        case .setTime(let u): try variant("SetTime") { try $0.encode(u, forKey: k("unix")) }
        case .unlock(let p): try variant("Unlock") { try $0.encode(p, forKey: k("passphrase")) }
        case .listEntries(let kind): try variant("ListEntries") { try $0.encode(kind, forKey: k("kind")) }
        case .getSecret(let id, let f, let ctx): try variant("GetSecret") {
            try $0.encode(id, forKey: k("id")); try $0.encode(f, forKey: k("field")); try $0.encode(ctx, forKey: k("context")) }
        case .getTotp(let id): try variant("GetTotp") { try $0.encode(id, forKey: k("id")) }
        case .addEntry(let e): try variant("AddEntry") { try $0.encode(e, forKey: k("entry")) }
        case .updateEntry(let e): try variant("UpdateEntry") { try $0.encode(e, forKey: k("entry")) }
        case .deleteEntry(let id): try variant("DeleteEntry") { try $0.encode(id, forKey: k("id")) }
        case .markRecoveryCodeUsed(let id, let i): try variant("MarkRecoveryCodeUsed") {
            try $0.encode(id, forKey: k("id")); try $0.encode(i, forKey: k("index")) }
        case .generateSshKey(let n, let c, let p): try variant("GenerateSshKey") {
            try $0.encode(n, forKey: k("name")); try $0.encode(c, forKey: k("comment")); try $0.encode(p, forKey: k("policy")) }
        case .sshSign(let pk, let d, let f, let h): try variant("SshSign") {
            try $0.encode(pk, forKey: k("public_key")); try $0.encode(d, forKey: k("data"))
            try $0.encode(f, forKey: k("flags")); try $0.encode(h, forKey: k("host_hint")) }
        case .ctap(let cbor, let o): try variant("Ctap") { try $0.encode(cbor, forKey: k("cbor")); try $0.encode(o, forKey: k("origin_hint")) }
        case .typeEntry(let id, let f, let l): try variant("TypeEntry") {
            try $0.encode(id, forKey: k("id")); try $0.encode(f, forKey: k("field")); try $0.encode(l, forKey: k("layout")) }
        case .export(let p): try variant("Export") { try $0.encode(p, forKey: k("passphrase")) }
        case .setRecoveryPassphrase(let p): try variant("SetRecoveryPassphrase") { try $0.encode(p, forKey: k("passphrase")) }
        case .getEntry(let id): try variant("GetEntry") { try $0.encode(id, forKey: k("id")) }
        case .exportChunk(let o): try variant("ExportChunk") { try $0.encode(o, forKey: k("offset")) }
        case .importBegin(let t): try variant("ImportBegin") { try $0.encode(t, forKey: k("total_len")) }
        case .importChunk(let o, let d): try variant("ImportChunk") { try $0.encode(o, forKey: k("offset")); try $0.encode(d, forKey: k("data")) }
        case .importCommit(let p, let m): try variant("ImportCommit") { try $0.encode(p, forKey: k("passphrase")); try $0.encode(m, forKey: k("mode")) }
        case .removePairedHost(let pk): try variant("RemovePairedHost") { try $0.encode(pk, forKey: k("public_key")) }
        case .renamePairedHost(let pk, let l): try variant("RenamePairedHost") { try $0.encode(pk, forKey: k("public_key")); try $0.encode(l, forKey: k("label")) }
        case .setSettings(let s): try variant("SetSettings") { try $0.encode(s, forKey: k("settings")) }
        case .setEntryPolicy(let id, let p): try variant("SetEntryPolicy") { try $0.encode(id, forKey: k("id")); try $0.encode(p, forKey: k("policy")) }
        }
    }
}

// MARK: - Response

public enum Response: Codable, Equatable, Sendable {
    case info(DeviceInfo)
    case ok
    case paired(label: String)
    case entries([EntrySummary])
    case secret(SecretValue)
    case totp(code: String, validUntil: UInt64)
    case entryId(EntryId)
    case entry(Entry)
    case sshKeys([SshPublicKey])
    case sshSignature([UInt8])
    case ctap([UInt8])
    case exportReady(totalLen: UInt32)
    case chunk(offset: UInt32, data: [UInt8])
    case pairedHosts([PairedHost])
    case settings(DeviceSettings)
    case passkeys([PasskeyIdentity])
    case error(ErrorCode)

    public init(from decoder: Decoder) throws {
        switch try Tagged.read(decoder) {
        case .unit(let t):
            guard t == "Ok" else { throw unknownVariant(t, "Response") }
            self = .ok
        case .data(let t, let c):
            let k = AnyKey(t)
            switch t {
            case "Info": self = .info(try c.decode(DeviceInfo.self, forKey: k))
            case "Paired": self = .paired(label: try c.nestedContainer(keyedBy: AnyKey.self, forKey: k).decode(String.self, forKey: AnyKey("label")))
            case "Entries": self = .entries(try c.decode([EntrySummary].self, forKey: k))
            case "Secret": self = .secret(try c.decode(SecretValue.self, forKey: k))
            case "Totp":
                let n = try c.nestedContainer(keyedBy: AnyKey.self, forKey: k)
                self = .totp(code: try n.decode(String.self, forKey: AnyKey("code")), validUntil: try n.decode(UInt64.self, forKey: AnyKey("valid_until")))
            case "EntryId": self = .entryId(try c.decode(EntryId.self, forKey: k))
            case "Entry": self = .entry(try c.decode(Entry.self, forKey: k))
            case "SshKeys": self = .sshKeys(try c.decode([SshPublicKey].self, forKey: k))
            case "SshSignature": self = .sshSignature(try c.decode([UInt8].self, forKey: k))
            case "Ctap": self = .ctap(try c.decode([UInt8].self, forKey: k))
            case "ExportReady": self = .exportReady(totalLen: try c.nestedContainer(keyedBy: AnyKey.self, forKey: k).decode(UInt32.self, forKey: AnyKey("total_len")))
            case "Chunk":
                let n = try c.nestedContainer(keyedBy: AnyKey.self, forKey: k)
                self = .chunk(offset: try n.decode(UInt32.self, forKey: AnyKey("offset")), data: try n.decode([UInt8].self, forKey: AnyKey("data")))
            case "PairedHosts": self = .pairedHosts(try c.decode([PairedHost].self, forKey: k))
            case "Settings": self = .settings(try c.decode(DeviceSettings.self, forKey: k))
            case "Passkeys": self = .passkeys(try c.decode([PasskeyIdentity].self, forKey: k))
            case "Error": self = .error(try c.decode(ErrorCode.self, forKey: k))
            default: throw unknownVariant(t, "Response")
            }
        }
    }

    public func encode(to encoder: Encoder) throws {
        if case .ok = self { try encodeUnit("Ok", encoder); return }
        var c = encoder.container(keyedBy: AnyKey.self)
        func k(_ s: String) -> AnyKey { AnyKey(s) }
        switch self {
        case .ok: break
        case .info(let v): try c.encode(v, forKey: k("Info"))
        case .paired(let l):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: k("Paired")); try n.encode(l, forKey: k("label"))
        case .entries(let v): try c.encode(v, forKey: k("Entries"))
        case .secret(let v): try c.encode(v, forKey: k("Secret"))
        case .totp(let code, let until):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: k("Totp"))
            try n.encode(code, forKey: k("code")); try n.encode(until, forKey: k("valid_until"))
        case .entryId(let v): try c.encode(v, forKey: k("EntryId"))
        case .entry(let v): try c.encode(v, forKey: k("Entry"))
        case .sshKeys(let v): try c.encode(v, forKey: k("SshKeys"))
        case .sshSignature(let v): try c.encode(v, forKey: k("SshSignature"))
        case .ctap(let v): try c.encode(v, forKey: k("Ctap"))
        case .exportReady(let t):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: k("ExportReady")); try n.encode(t, forKey: k("total_len"))
        case .chunk(let o, let d):
            var n = c.nestedContainer(keyedBy: AnyKey.self, forKey: k("Chunk"))
            try n.encode(o, forKey: k("offset")); try n.encode(d, forKey: k("data"))
        case .pairedHosts(let v): try c.encode(v, forKey: k("PairedHosts"))
        case .settings(let v): try c.encode(v, forKey: k("Settings"))
        case .passkeys(let v): try c.encode(v, forKey: k("Passkeys"))
        case .error(let v): try c.encode(v, forKey: k("Error"))
        }
    }
}

// MARK: - Envelope & session events

public struct Envelope<T: Codable & Sendable>: Codable, Sendable {
    public var id: UInt32
    public var body: T
    public init(id: UInt32, body: T) { self.id = id; self.body = body }
}

/// JSON returned by `Session.onFrame` (serde externally tagged):
/// `{"SendFrame":[..]}`, `"Established"`, `{"Response":{"id":1,"body":..}}`, `{"PlainError":..}`.
public enum SessionEvent: Codable, Sendable {
    case sendFrame([UInt8])
    case established
    case response(Envelope<Response>)
    case plainError(JSONValue)

    public init(from decoder: Decoder) throws {
        switch try Tagged.read(decoder) {
        case .unit(let t):
            guard t == "Established" else { throw unknownVariant(t, "SessionEvent") }
            self = .established
        case .data(let t, let c):
            let k = AnyKey(t)
            switch t {
            case "SendFrame": self = .sendFrame(try c.decode([UInt8].self, forKey: k))
            case "Response": self = .response(try c.decode(Envelope<Response>.self, forKey: k))
            case "PlainError": self = .plainError(try c.decode(JSONValue.self, forKey: k))
            default: throw unknownVariant(t, "SessionEvent")
            }
        }
    }
    public func encode(to encoder: Encoder) throws {
        if case .established = self { try encodeUnit("Established", encoder); return }
        var c = encoder.container(keyedBy: AnyKey.self)
        switch self {
        case .established: break
        case .sendFrame(let f): try c.encode(f, forKey: AnyKey("SendFrame"))
        case .response(let r): try c.encode(r, forKey: AnyKey("Response"))
        case .plainError(let e): try c.encode(e, forKey: AnyKey("PlainError"))
        }
    }
}

public enum PrismJSON {
    public static let encoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e }()
    public static let decoder = JSONDecoder()
    public static func string<T: Encodable>(_ v: T) throws -> String {
        String(decoding: try encoder.encode(v), as: UTF8.self)
    }
    public static func decode<T: Decodable>(_ type: T.Type, from s: String) throws -> T {
        try decoder.decode(type, from: Data(s.utf8))
    }
}
