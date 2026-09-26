import XCTest
import Foundation
import Crypto
@testable import SmartHealthCheckin
@testable import SmartHealthCheckinModel
@testable import SmartHealthCheckinMdoc
@testable import SmartHealthCheckinCBOR

// The spec's conformance cases (github.com/smart-health-checkin/spec,
// conformance/), fetched at a pinned ref into spec-conformance/ by
// scripts/fetch-conformance.sh. Every claimed case must pass except those in
// conformance/known-failures.json, which must still fail: a listed case that
// passes fails this test until it is removed from the list.
//
// wallet-response cases only build the credential here, into
// .build/conformance-wallet/; CI then checks it with the spec's reference
// verifier (conformance/reference/verify-wallet-output.ts, the JS client).
final class SpecConformanceTests: XCTestCase {
    static let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static let casesRoot = packageRoot.appendingPathComponent("spec-conformance")
    static let walletOut = packageRoot.appendingPathComponent(".build/conformance-wallet")

    func testSpecConformanceCases() throws {
        let manifestURL = Self.casesRoot.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw XCTSkip("spec-conformance/ missing: run scripts/fetch-conformance.sh")
        }
        try FileManager.default.createDirectory(at: Self.walletOut, withIntermediateDirectories: true)
        let manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as! [String: Any]
        let config = try JSONSerialization.jsonObject(with: Data(contentsOf: Self.packageRoot.appendingPathComponent("conformance/known-failures.json"))) as! [String: Any]
        let claims = Set(config["claims"] as! [String])
        let known = config["knownFailures"] as! [String: Any]
        var unexpectedFailures: [String] = []
        var unexpectedPasses: [String] = []
        var unreportedWarnings: [String] = []
        var ran = 0
        for c in manifest["cases"] as! [[String: Any]] {
            let id = c["id"] as! String
            let capability = c["capability"] as! String
            if (c["status"] as? String) == "pending" || !claims.contains(capability) { continue }
            ran += 1
            reportedWarnings = []
            let passed = (try? run(c)) ?? false
            print("CONFORMANCE \(passed ? "pass" : "fail") \(id)")
            // [RCV-1] Reporting the expected warnings is advisory: logged, not gated.
            let expectedWarnings = (c["expected"] as! [String: Any])["warnings"] as? [String] ?? []
            let missing = expectedWarnings.filter { !reportedWarnings.contains($0) }
            if passed && outcome(c) == "warn" && !missing.isEmpty { unreportedWarnings.append("\(id): \(missing)") }
            if capability == "wallet-response" {
                // Here we only build the credential; the reference verifier judges it (and applies known failures).
                if !passed { unexpectedFailures.append("\(id): couldn't build a credential") }
            } else if known[id] != nil {
                if passed { unexpectedPasses.append(id) }
            } else if !passed {
                unexpectedFailures.append("\(id): \(c["description"] as! String)")
            }
        }
        print("CONFORMANCE advisory: \(unreportedWarnings.count) warn cases accepted without reporting the expected code")
        for w in unreportedWarnings { print("CONFORMANCE advisory: \(w)") }
        if !unexpectedFailures.isEmpty || !unexpectedPasses.isEmpty {
            var msg = "Conformance (\(ran) cases run):\n"
            if !unexpectedFailures.isEmpty { msg += "Unexpected failures:\n  " + unexpectedFailures.joined(separator: "\n  ") + "\n" }
            if !unexpectedPasses.isEmpty { msg += "Now passing, remove from conformance/known-failures.json:\n  " + unexpectedPasses.joined(separator: "\n  ") + "\n" }
            XCTFail(msg)
        }
    }

    // MARK: - One case

    private func url(_ c: [String: Any], _ key: String) -> URL {
        Self.casesRoot.appendingPathComponent((c["inputs"] as! [String: String])[key]!)
    }
    private func data(_ c: [String: Any], _ key: String) throws -> Data { try Data(contentsOf: url(c, key)) }
    private func text(_ c: [String: Any], _ key: String) throws -> String {
        String(decoding: try data(c, key), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    private func output(_ c: [String: Any], _ key: String) throws -> Data {
        let outputs = (c["expected"] as! [String: Any])["outputs"] as! [String: String]
        return try Data(contentsOf: Self.casesRoot.appendingPathComponent(outputs[key]!))
    }
    private func outcome(_ c: [String: Any]) -> String { (c["expected"] as! [String: Any])["outcome"] as! String }
    private func hasOutput(_ c: [String: Any], _ key: String) -> Bool {
        ((c["expected"] as! [String: Any])["outputs"] as? [String: String])?[key] != nil
    }

    /// `attempt` throws when the library rejects the input and otherwise returns
    /// whether its outputs match. accept and warn both require accepting;
    /// reporting the warning is advisory (RCV-1).
    private func judge(_ c: [String: Any], _ attempt: () throws -> Bool) -> Bool {
        let result: Bool?
        do { result = try attempt() } catch { result = nil }
        switch outcome(c) {
        case "reject": return result == nil
        case "warn-or-reject": return result != false
        default: return result == true
        }
    }
    private struct Rejected: Error {}

    /// Warning codes the library reported for the current case.
    private var reportedWarnings: Set<String> = []
    private func note(_ ws: [CheckinWarning]) { for w in ws { reportedWarnings.insert(w.code) } }

    private func expectedMap(_ c: [String: Any], _ key: String) -> [String: String] {
        (c["expected"] as! [String: Any])[key] as? [String: String] ?? [:]
    }

    /// Per-Artifact expectations: "accepted" ids must be usable, "rejected" ids disregarded.
    private func artifactsMatch(_ c: [String: Any], usable: [String], disregarded: [String?]) -> Bool {
        for (id, want) in expectedMap(c, "artifacts") {
            let ok = want == "accepted" ? usable.contains(id) && !disregarded.contains(id) : disregarded.contains(id) && !usable.contains(id)
            if !ok { print("CONFORMANCE detail: artifact \(id) expected \(want)"); return false }
        }
        return true
    }

    /// Did the library reach the expected verdict (and outputs)?
    private func run(_ c: [String: Any]) throws -> Bool {
        switch c["capability"] as! String {
        case "request-json":
            return judge(c) {
                let r = try SmartHealthCheckinRequest.parse(try data(c, "request"))
                if SmartHealthCheckinValidator.validate(request: r).hasErrors { throw Rejected() }
                let unsupported = SmartHealthCheckinValidator.unsupportedItems(in: r)
                for (id, want) in expectedMap(c, "items") where want == "unsupported" && unsupported[id] == nil {
                    print("CONFORMANCE detail: item \(id) expected unsupported"); return false
                }
                return true
            }
        case "response-json":
            return judge(c) {
                let resp = try SmartHealthCheckinResponse.parse(try data(c, "response"))
                for (id, want) in expectedMap(c, "items") where want == "unknown" && !resp.disregardedStatus.contains(where: { $0.id == id }) {
                    return false
                }
                return artifactsMatch(c, usable: resp.artifacts.map(\.id), disregarded: resp.disregardedArtifacts.map(\.id))
            }
        case "cross-validation":
            return judge(c) {
                let req = try SmartHealthCheckinRequest.parse(try data(c, "request"))
                let resp = try SmartHealthCheckinResponse.parse(try data(c, "response"))
                let check = SmartHealthCheckinValidator.crossCheck(request: req, response: resp)
                if check.report.hasErrors { throw Rejected() }
                for (id, want) in expectedMap(c, "items") where want == "unknown" {
                    guard case .unknown? = check.itemOutcomes[id] else { return false }
                }
                return artifactsMatch(c, usable: check.usableArtifacts.map(\.id), disregarded: check.disregardedArtifacts.map(\.id))
            }
        case "request-cbor":
            return judge(c) {
                let (proto, dr, ei) = try mdocRequestData(try data(c, "navigatorArgument"))
                let (parsed, _) = try CheckinWallet.handleRequest(deviceRequestBase64Url: dr, encryptionInfoBase64Url: ei, origin: "https://clinic.example", protocol: proto)
                note(parsed.warnings)
                if !hasOutput(c, "smartRequest") { return true }
                return try sameJSON(parsed.smartRequest.toJSONData(), try output(c, "smartRequest"))
            }
        case "transcript":
            let t = SessionTranscript.dcapi(encryptionInfoBase64Url: try text(c, "encryptionInfo"), origin: try text(c, "origin"))
            return t == (try output(c, "sessionTranscript"))
        case "hpke-open":
            return judge(c) {
                let plaintext = try open(c)
                if !hasOutput(c, "deviceResponse") { return true }
                return plaintext == (try output(c, "deviceResponse"))
            }
        case "mdoc-verify":
            return judge(c) {
                let parsed = try DeviceResponseParser.parse(try data(c, "deviceResponse"))
                let now = iso8601(try text(c, "now"))
                let v = try DeviceResponseValidator.validate(parsed, sessionTranscript: try data(c, "sessionTranscript"), options: .init(
                    docType: SmartHealthCheckinConstants.mdocDocType,
                    namespace: SmartHealthCheckinConstants.mdocNamespace,
                    element: SmartHealthCheckinConstants.mdocElementIdentifier,
                    now: now ?? Date()))
                note(v.warnings)
                // [RCV-2] Only the fail steps reject; an accept case must also verify cleanly.
                if outcome(c) == "accept" { return v.issuerSignatureValid && v.deviceSignatureValid && v.digestMatch && v.warnings.isEmpty }
                return true
            }
        case "wallet-response":
            let (proto, dr, ei) = try mdocRequestData(try data(c, "navigatorArgument"))
            let (_, assembler) = try CheckinWallet.handleRequest(deviceRequestBase64Url: dr, encryptionInfoBase64Url: ei, origin: try text(c, "origin"), protocol: proto)
            let response = try SmartHealthCheckinResponse.parse(try data(c, "smartResponse"))
            let b64u = try assembler.reply(smartResponse: response, issuerKey: P256.Signing.PrivateKey(), deviceKey: P256.Signing.PrivateKey())
            let credential = try JSONSerialization.data(withJSONObject: ["protocol": "org-iso-mdoc", "data": ["response": b64u]])
            let id = (c["id"] as! String).replacingOccurrences(of: "/", with: "_")
            try credential.write(to: Self.walletOut.appendingPathComponent("\(id).json"))
            return true
        default:
            throw NSError(domain: "conformance", code: 1)
        }
    }

    private func iso8601(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    /// The host's job: pick the mdoc entry from the navigator.credentials.get
    /// argument. The package never sees `protocol`; like the other runners'
    /// hosts, this one prefers org-iso-mdoc and otherwise takes the first
    /// entry with mdoc data (a wrong protocol is a warning, WRQ-2).
    private func mdocRequestData(_ json: Data) throws -> (String?, String, String) {
        let arg = try JSONSerialization.jsonObject(with: json) as! [String: Any]
        let all = (arg["digital"] as? [String: Any])?["requests"] as? [[String: Any]] ?? []
        let requests = all.filter { ($0["protocol"] as? String) == "org-iso-mdoc" } + all.filter { ($0["protocol"] as? String) != "org-iso-mdoc" }
        for r in requests {
            if let d = r["data"] as? [String: Any], let dr = d["deviceRequest"] as? String, let ei = d["encryptionInfo"] as? String {
                return (r["protocol"] as? String, dr, ei)
            }
        }
        throw NSError(domain: "conformance", code: 2, userInfo: [NSLocalizedDescriptionKey: "no org-iso-mdoc request"])
    }

    /// Verifier side: open a credential with the case's key and transcript,
    /// with the package's receiver rules ([VRS-2], [VRS-3]).
    private func open(_ c: [String: Any]) throws -> Data {
        let cred = try JSONSerialization.jsonObject(with: try data(c, "credential")) as! [String: Any]
        guard let response = (cred["data"] as? [String: Any])?["response"] as? String else {
            throw NSError(domain: "conformance", code: 3)
        }
        if let p = cred["protocol"] as? String, p != SmartHealthCheckinConstants.dcApiProtocol { reportedWarnings.insert("protocol") }
        if Base64URL.isPadded(response) { reportedWarnings.insert("base64url-padding") }
        let key = try FixtureConformanceTests.loadP256KeyAgreementPrivateKeyFromJWK(url: url(c, "recipientPrivateJwk"))
        let st = SessionTranscript.dcapi(encryptionInfoBase64Url: try text(c, "encryptionInfo"), origin: try text(c, "origin"))
        let env = try DCAPIResponse.decodeLenient(try Base64URL.decode(response))
        note(env.warnings)
        return try CheckinHPKE.open(ciphertext: env.ciphertext, encapsulatedKey: env.enc, recipientPrivateKey: key, info: st, aad: Data())
    }

    private func sameJSON(_ a: Data, _ b: Data) throws -> Bool {
        let norm = { (d: Data) throws -> Data in
            try JSONSerialization.data(withJSONObject: JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]), options: [.sortedKeys])
        }
        return try norm(a) == norm(b)
    }
}
