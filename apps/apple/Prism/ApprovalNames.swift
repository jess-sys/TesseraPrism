import Foundation
import PrismKit

extension ApprovalPolicy {
    /// Wording for the device-wide defaults and for explicit per-entry overrides.
    var label: String {
        switch self {
        case .always: return "Always ask"
        case .session: return "Once per unlock"
        case .never: return "Never ask"
        case .default: return "Device default"
        }
    }
}

extension ApprovalOp {
    var label: String {
        switch self {
        case .password: return "Passwords"
        case .totp: return "One-time codes"
        case .sshSign: return "SSH sign-in"
        case .passkey: return "Passkey sign-in"
        case .recoveryCodes: return "Recovery codes"
        case .typeOverUsb: return "Type over USB"
        case .modify: return "Add & edit entries"
        case .delete: return "Delete entries"
        }
    }
    /// Passkeys never skip user presence entirely.
    var choices: [ApprovalPolicy] { self == .passkey ? [.always, .session] : [.always, .session, .never] }
}

extension EntryKind {
    /// The operation whose device default applies to entries of this kind.
    var approvalOp: ApprovalOp {
        switch self {
        case .password: return .password
        case .totp: return .totp
        case .passkey: return .passkey
        case .sshKey: return .sshSign
        case .recoveryCodes: return .recoveryCodes
        }
    }
}

enum PasswordCacheDuration: UInt32, CaseIterable {
    case off = 0, hour = 3600, day = 86_400, week = 604_800, month = 2_592_000
    var label: String {
        switch self {
        case .off: return "Off"
        case .hour: return "1 hour"
        case .day: return "1 day"
        case .week: return "7 days"
        case .month: return "30 days"
        }
    }
}
