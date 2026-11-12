import XCTest
@testable import PrismKit

/// Fixtures are written by hand following serde_json's default encodings (what prism-core produces).
final class ModelsTests: XCTestCase {
    func json(_ s: String) -> Any { try! JSONSerialization.jsonObject(with: Data(s.utf8), options: [.fragmentsAllowed]) }
    func assertEncodes<T: Encodable>(_ v: T, _ expected: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let data = try PrismJSON.encoder.encode(v)
        let actual = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        XCTAssertEqual(actual as? NSObject, json(expected) as? NSObject, String(decoding: data, as: UTF8.self), file: file, line: line)
    }
    func roundTrip<T: Codable & Equatable>(_ v: T, _ s: String, file: StaticString = #filePath, line: UInt = #line) throws {
        try assertEncodes(v, s, file: file, line: line)
        XCTAssertEqual(try PrismJSON.decode(T.self, from: s), v, file: file, line: line)
    }

    let id = EntryId(bytes: Array(0..<16))
    let idJSON = "[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]"

    func testEntryIdHex() {
        XCTAssertEqual(id.hex, "000102030405060708090a0b0c0d0e0f")
        XCTAssertEqual(EntryId(hex: id.hex), id)
        XCTAssertNil(EntryId(hex: "zz"))
    }

    func testPasswordEntry() throws {
        let e = Entry(id: id, title: "GitHub", tags: ["dev"], created: 10, modified: 20, policy: .session,
                      data: .password(Password(username: "me", password: "pw", url: "https://github.com", notes: "", totp: nil)))
        try roundTrip(e, """
        {"id":\(idJSON),"title":"GitHub","tags":["dev"],"created":10,"modified":20,"policy":"Session",
         "data":{"Password":{"username":"me","password":"pw","url":"https://github.com","notes":"","totp":null}}}
        """)
    }

    func testTotpEntryAndNullUrl() throws {
        let t = Totp(issuer: "X", account: "a", secret: [1, 2, 3], algorithm: .sha256, digits: 8, period: 60)
        try roundTrip(EntryData.totp(t), #"{"Totp":{"issuer":"X","account":"a","secret":[1,2,3],"algorithm":"Sha256","digits":8,"period":60}}"#)
        try assertEncodes(Password(username: "u", password: "p"), #"{"username":"u","password":"p","url":null,"notes":"","totp":null}"#)
    }

    func testSshKeySource() throws {
        try roundTrip(SshKeySource.derived(index: 3), #"{"Derived":{"index":3}}"#)
        try roundTrip(SshKeySource.imported(secret: [9, 9]), #"{"Imported":{"secret":[9,9]}}"#)
    }

    func testSummary() throws {
        let s = EntrySummary(id: id, kind: .sshKey, title: "t", subtitle: "s", url: nil, tags: [], modified: 5, hasTotp: true, policy: .never)
        try roundTrip(s, """
        {"id":\(idJSON),"kind":"SshKey","title":"t","subtitle":"s","url":null,"tags":[],"modified":5,"has_totp":true,"policy":"Never"}
        """)
    }

    func testSettings() throws {
        try roundTrip(DeviceSettings(), #"{"approvals":{"delete":"Always","modify":"Always","password":"Always","passkey":"Always","recovery_codes":"Always","ssh_sign":"Always","totp":"Always","type_over_usb":"Always"},"auto_lock_secs":180,"buzzer":true,"keyboard_layout":"Us","orientation":"Portrait","owner_info":null,"password_cache_secs":0,"sleep_mode":"PowerOff"}"#)
        var s = DeviceSettings(passwordCacheSecs: 3600)
        s.approvals[.password] = .never; s.approvals[.passkey] = .session
        let back = try PrismJSON.decode(DeviceSettings.self, from: try PrismJSON.string(s))
        XCTAssertEqual(back, s)
        XCTAssertEqual(back.approvals.password, .never)
    }

    func testApprovalPolicyDefault() throws {
        try roundTrip(ApprovalPolicy.default, #""Default""#)
        try roundTrip(Request.setEntryPolicy(id: id, policy: .default), #"{"SetEntryPolicy":{"id":\#(idJSON),"policy":"Default"}}"#)
        try roundTrip(Request.passwordSnapshot, #""PasswordSnapshot""#)
    }

    func testRequests() throws {
        try roundTrip(Request.getInfo, #""GetInfo""#)
        try roundTrip(Request.lock, #""Lock""#)
        try roundTrip(Request.setTime(unix: 1700000000), #"{"SetTime":{"unix":1700000000}}"#)
        try roundTrip(Request.listEntries(kind: nil), #"{"ListEntries":{"kind":null}}"#)
        try roundTrip(Request.listEntries(kind: .totp), #"{"ListEntries":{"kind":"Totp"}}"#)
        try roundTrip(Request.getSecret(id: id, field: .password, context: "github.com"),
                      #"{"GetSecret":{"id":\#(idJSON),"field":"Password","context":"github.com"}}"#)
        try roundTrip(Request.deleteEntry(id: id), #"{"DeleteEntry":{"id":\#(idJSON)}}"#)
        try roundTrip(Request.ctap(cbor: [2, 161], originHint: nil), #"{"Ctap":{"cbor":[2,161],"origin_hint":null}}"#)
        try roundTrip(Request.sshSign(publicKey: [1], data: [2], flags: 0, hostHint: "gh"),
                      #"{"SshSign":{"public_key":[1],"data":[2],"flags":0,"host_hint":"gh"}}"#)
        try roundTrip(Request.importChunk(offset: 4096, data: [7]), #"{"ImportChunk":{"offset":4096,"data":[7]}}"#)
        try roundTrip(Request.importCommit(passphrase: "x", mode: .merge), #"{"ImportCommit":{"passphrase":"x","mode":"Merge"}}"#)
        try roundTrip(Request.generateSshKey(name: "n", comment: "c", policy: .always),
                      #"{"GenerateSshKey":{"name":"n","comment":"c","policy":"Always"}}"#)
        try roundTrip(Request.export(passphrase: "pw"), #"{"Export":{"passphrase":"pw"}}"#)
        try roundTrip(Request.setRecoveryPassphrase(passphrase: "pw"), #"{"SetRecoveryPassphrase":{"passphrase":"pw"}}"#)
        try roundTrip(Request.getEntry(id: id), #"{"GetEntry":{"id":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]}}"#)
        try roundTrip(Request.listPasskeys, #""ListPasskeys""#)
        try roundTrip(Request.renamePairedHost(publicKey: [1, 2], label: "Mac"), #"{"RenamePairedHost":{"public_key":[1,2],"label":"Mac"}}"#)
    }

    func testEnvelope() throws {
        try assertEncodes(Envelope(id: 7, body: Request.getInfo), #"{"id":7,"body":"GetInfo"}"#)
    }

    func testResponses() throws {
        try roundTrip(Response.ok, #""Ok""#)
        try roundTrip(Response.paired(label: "mac"), #"{"Paired":{"label":"mac"}}"#)
        try roundTrip(Response.totp(code: "123456", validUntil: 90), #"{"Totp":{"code":"123456","valid_until":90}}"#)
        try roundTrip(Response.secret(.text("hunter2")), #"{"Secret":{"Text":"hunter2"}}"#)
        try roundTrip(Response.secret(.list(["a", "b"])), #"{"Secret":{"List":["a","b"]}}"#)
        try roundTrip(Response.sshKeys([]), #"{"SshKeys":[]}"#)
        try roundTrip(Response.entryId(id), #"{"EntryId":\#(idJSON)}"#)
        try roundTrip(Response.ctap([0, 1]), #"{"Ctap":[0,1]}"#)
        try roundTrip(Response.exportReady(totalLen: 100), #"{"ExportReady":{"total_len":100}}"#)
        try roundTrip(Response.chunk(offset: 8, data: [1, 2]), #"{"Chunk":{"offset":8,"data":[1,2]}}"#)
        try roundTrip(Response.error(.notPaired), #"{"Error":"NotPaired"}"#)
        let pk = [UInt8](repeating: 1, count: 32)
        let info = DeviceInfo(fwVersion: "0.1.0", devicePubkey: pk, locked: true, initialized: true, batteryPct: 80, charging: false, entryCount: 3, timeValid: true)
        try roundTrip(Response.info(info), """
        {"Info":{"fw_version":"0.1.0","device_pubkey":\(pk),"locked":true,"initialized":true,"battery_pct":80,"charging":false,"entry_count":3,"time_valid":true}}
        """)
    }

    func testSessionEvent() throws {
        guard case .established = try PrismJSON.decode(SessionEvent.self, from: #""Established""#) else { return XCTFail() }
        let e = try PrismJSON.decode(SessionEvent.self, from: #"{"Response":{"id":3,"body":{"Error":"Locked"}}}"#)
        guard case .response(let env) = e else { return XCTFail() }
        XCTAssertEqual(env.id, 3); XCTAssertEqual(env.body, .error(.locked))
        guard case .sendFrame(let f) = try PrismJSON.decode(SessionEvent.self, from: #"{"SendFrame":[1,2,3]}"#) else { return XCTFail() }
        XCTAssertEqual(f, [1, 2, 3])
    }
}
