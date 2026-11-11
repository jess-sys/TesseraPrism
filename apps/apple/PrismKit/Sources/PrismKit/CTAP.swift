import Foundation

/// CTAP2 request builders / response parsers used by the AutoFill credential provider.
/// `Request.ctap(cbor:)` carries `[cmd byte] ++ CBOR`; the response is `[status byte] ++ CBOR`.
public enum CTAP {
    public enum Command: UInt8 { case makeCredential = 0x01, getAssertion = 0x02, getInfo = 0x04 }
    public enum CTAPError: Error, LocalizedError {
        case status(UInt8), malformed(String)
        public var errorDescription: String? {
            switch self {
            case .status(let s): return "CTAP error 0x" + String(s, radix: 16)
            case .malformed(let m): return "Malformed CTAP response: \(m)"
            }
        }
    }

    public static func getAssertionRequest(rpId: String, clientDataHash: [UInt8], allowCredentialIds: [[UInt8]],
                                           userVerification: Bool = true) -> [UInt8] {
        var pairs: [(CBOR, CBOR)] = [(.int(1), .text(rpId)), (.int(2), .bytes(clientDataHash))]
        if !allowCredentialIds.isEmpty {
            pairs.append((.int(3), .array(allowCredentialIds.map {
                .map([(.text("type"), .text("public-key")), (.text("id"), .bytes($0))]) })))
        }
        pairs.append((.int(5), .map([(.text("up"), .bool(true)), (.text("uv"), .bool(userVerification))])))
        return [Command.getAssertion.rawValue] + CBOR.map(pairs).encode()
    }

    public static func makeCredentialRequest(rpId: String, rpName: String, clientDataHash: [UInt8], userId: [UInt8],
                                             userName: String, userDisplayName: String,
                                             algorithms: [Int64] = [-7, -8], residentKey: Bool = true) -> [UInt8] {
        let map: [(CBOR, CBOR)] = [
            (.int(1), .bytes(clientDataHash)),
            (.int(2), .map([(.text("id"), .text(rpId)), (.text("name"), .text(rpName))])),
            (.int(3), .map([(.text("id"), .bytes(userId)), (.text("name"), .text(userName)),
                            (.text("displayName"), .text(userDisplayName))])),
            (.int(4), .array(algorithms.map { .map([(.text("alg"), .int($0)), (.text("type"), .text("public-key"))]) })),
            (.int(7), .map([(.text("rk"), .bool(residentKey)), (.text("uv"), .bool(true))])),
        ]
        return [Command.makeCredential.rawValue] + CBOR.map(map).encode()
    }

    public struct Assertion: Sendable {
        public var credentialId: [UInt8]
        public var authenticatorData: [UInt8]
        public var signature: [UInt8]
        public var userHandle: [UInt8]?
    }

    public struct Registration: Sendable {
        public var credentialId: [UInt8]
        public var authenticatorData: [UInt8]
        public var attestationObject: [UInt8]
    }

    static func body(_ response: [UInt8]) throws -> CBOR {
        guard let status = response.first else { throw CTAPError.malformed("empty") }
        guard status == 0 else { throw CTAPError.status(status) }
        return try CBOR.decode(Array(response.dropFirst()))
    }

    public static func parseAssertion(_ response: [UInt8], fallbackCredentialId: [UInt8] = []) throws -> Assertion {
        let m = try body(response)
        guard let authData = m[2]?.byteString, let sig = m[3]?.byteString else { throw CTAPError.malformed("assertion fields") }
        let credId = m[1]?["id"]?.byteString ?? fallbackCredentialId
        return Assertion(credentialId: credId, authenticatorData: authData, signature: sig, userHandle: m[4]?["id"]?.byteString)
    }

    public static func parseRegistration(_ response: [UInt8]) throws -> Registration {
        let m = try body(response)
        guard let fmt = m[1]?.string, let authData = m[2]?.byteString, let attStmt = m[3] else { throw CTAPError.malformed("registration fields") }
        // authData: rpIdHash(32) flags(1) signCount(4) [aaguid(16) credIdLen(2) credId ...]
        guard authData.count >= 55, authData[32] & 0x40 != 0 else { throw CTAPError.malformed("no attested credential data") }
        let len = Int(authData[53]) << 8 | Int(authData[54])
        guard authData.count >= 55 + len else { throw CTAPError.malformed("credential id length") }
        let credId = Array(authData[55..<55 + len])
        let att = CBOR.map([(.text("fmt"), .text(fmt)), (.text("attStmt"), attStmt), (.text("authData"), .bytes(authData))])
        return Registration(credentialId: credId, authenticatorData: authData, attestationObject: att.encode())
    }
}
