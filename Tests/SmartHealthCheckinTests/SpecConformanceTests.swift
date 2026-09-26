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
        var ran = 0
        for c in manifest["cases"] as! [[String: Any]] {
            let id = c["id"] as! String
            let capability = c["capability"] as! String
            if (c["status"] as? String) == "pending" || !claims.contains(capability) { continue }
            ran += 1
            let passed = (try? run(c)) ?? false
            print("CONFORMANCE \(passed ? "pass" : "fail") \(id)")
            if known[id] != nil {
                if passed { unexpectedPasses.append(id) }
            } else if !passed {
                unexpectedFailures.append("\(id): \(c["description"] as! String)")
            }
        }
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
    private func expectedValid(_ c: [String: Any]) -> Bool { (c["expected"] as! [String: Any])["valid"] as! Bool }

    /// Did the library reach the expected verdict (and outputs)?
    private func run(_ c: [String: Any]) throws -> Bool {
        let valid = expectedValid(c)
        func verdict(_ check: () throws -> Bool) -> Bool {
            do { return try check() == valid } catch { return !valid }
        }
        switch c["capability"] as! String {
        case "request-json":
            return verdict {
                let r = try SmartHealthCheckinRequest.parse(try data(c, "request"))
                return !SmartHealthCheckinValidator.validate(request: r).hasErrors
            }
        case "response-json":
            return verdict { _ = try SmartHealthCheckinResponse.parse(try data(c, "response")); return true }
        case "cross-validation":
            return verdict {
                let req = try SmartHealthCheckinRequest.parse(try data(c, "request"))
                let resp = try SmartHealthCheckinResponse.parse(try data(c, "response"))
                return !SmartHealthCheckinValidator.crossValidate(request: req, response: resp).hasErrors
            }
        case "request-cbor":
            return verdict {
                let (dr, ei) = try mdocRequestData(try data(c, "navigatorArgument"))
                let (parsed, _) = try CheckinWallet.handleRequest(deviceRequestBase64Url: dr, encryptionInfoBase64Url: ei, origin: "https://clinic.example")
                _ = try EncryptionInfo.decode(try Base64URL.decode(ei))
                if parsed.smartRequestValidation.hasErrors { return false }
                if !valid { return true }
                return try sameJSON(parsed.smartRequest.toJSONData(), try output(c, "smartRequest"))
            }
        case "transcript":
            let t = SessionTranscript.dcapi(encryptionInfoBase64Url: try text(c, "encryptionInfo"), origin: try text(c, "origin"))
            return t == (try output(c, "sessionTranscript"))
        case "hpke-open":
            return verdict {
                let plaintext = try open(c)
                return valid ? plaintext == (try output(c, "deviceResponse")) : true
            }
        case "mdoc-verify":
            return verdict {
                let parsed = try DeviceResponseParser.parse(try data(c, "deviceResponse"))
                let v = try DeviceResponseValidator.validate(parsed, sessionTranscript: try data(c, "sessionTranscript"), options: .init(
                    docType: SmartHealthCheckinConstants.mdocDocType,
                    namespace: SmartHealthCheckinConstants.mdocNamespace,
                    element: SmartHealthCheckinConstants.mdocElementIdentifier))
                return v.issuerSignatureValid && v.deviceSignatureValid && v.digestMatch
            }
        case "wallet-response":
            let (dr, ei) = try mdocRequestData(try data(c, "navigatorArgument"))
            let (_, assembler) = try CheckinWallet.handleRequest(deviceRequestBase64Url: dr, encryptionInfoBase64Url: ei, origin: try text(c, "origin"))
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

    /// The host's job: pick the org-iso-mdoc entry from the navigator.credentials.get argument.
    private func mdocRequestData(_ json: Data) throws -> (String, String) {
        let arg = try JSONSerialization.jsonObject(with: json) as! [String: Any]
        let requests = (arg["digital"] as? [String: Any])?["requests"] as? [[String: Any]] ?? []
        for r in requests where (r["protocol"] as? String) == "org-iso-mdoc" {
            if let d = r["data"] as? [String: Any], let dr = d["deviceRequest"] as? String, let ei = d["encryptionInfo"] as? String {
                return (dr, ei)
            }
        }
        throw NSError(domain: "conformance", code: 2, userInfo: [NSLocalizedDescriptionKey: "no org-iso-mdoc request"])
    }

    /// Verifier side: open a credential with the case's key and transcript.
    private func open(_ c: [String: Any]) throws -> Data {
        let cred = try JSONSerialization.jsonObject(with: try data(c, "credential")) as! [String: Any]
        guard (cred["protocol"] as? String) == "org-iso-mdoc",
              let response = (cred["data"] as? [String: Any])?["response"] as? String else {
            throw NSError(domain: "conformance", code: 3)
        }
        let key = try FixtureConformanceTests.loadP256KeyAgreementPrivateKeyFromJWK(url: url(c, "recipientPrivateJwk"))
        let st = SessionTranscript.dcapi(encryptionInfoBase64Url: try text(c, "encryptionInfo"), origin: try text(c, "origin"))
        let (enc, ciphertext) = try DCAPIResponse.decode(try Base64URL.decode(response))
        return try CheckinHPKE.open(ciphertext: ciphertext, encapsulatedKey: enc, recipientPrivateKey: key, info: st, aad: Data())
    }

    private func sameJSON(_ a: Data, _ b: Data) throws -> Bool {
        let norm = { (d: Data) throws -> Data in
            try JSONSerialization.data(withJSONObject: JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]), options: [.sortedKeys])
        }
        return try norm(a) == norm(b)
    }
}
