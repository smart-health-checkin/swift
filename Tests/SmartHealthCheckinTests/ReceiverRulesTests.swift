// SPDX-License-Identifier: MIT
//
// Behavior the spec's conformance cases don't reach directly: origin
// serialization ([TR-2]), the certificates a producer attaches ([WRS-4],
// [RA-1]), the Wallet's own producer check, and what the host sees.

import XCTest
import Crypto
@testable import SmartHealthCheckin
@testable import SmartHealthCheckinModel
@testable import SmartHealthCheckinMdoc
@testable import SmartHealthCheckinCBOR

final class ReceiverRulesTests: XCTestCase {

    func request() -> SmartHealthCheckinRequest {
        SmartHealthCheckinRequest(id: "req-rr", items: [
            .init(id: "patient", title: "Patient",
                  content: .selectionFhir(.init(profiles: ["http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient"])),
                  accept: [SmartHealthCheckinConstants.mediaTypeFhirJson]),
            .init(id: "odd", title: "Something else",
                  content: .ext(kind: "example.unknown", members: []),
                  accept: [SmartHealthCheckinConstants.mediaTypeFhirJson]),
        ], fhirVersions: ["4.0.1"])
    }

    func patientResponse(_ req: SmartHealthCheckinRequest) -> SmartHealthCheckinResponse {
        SmartHealthCheckinResponse(
            requestId: req.id,
            artifacts: [.fhirJson(.init(id: "a1", fulfills: ["patient"], fhirVersion: "4.0.1",
                                        value: .object([("resourceType", .string("Patient"))])))],
            requestStatus: [.init(item: "patient", status: .fulfilled), .init(item: "odd", status: .unsupported)]
        )
    }

    // [TR-2] The ASCII serialization of an origin.
    func testOriginSerialization() {
        XCTAssertEqual(CheckinOrigin.serialize("https://clinic.example/"), "https://clinic.example")
        XCTAssertEqual(CheckinOrigin.serialize("https://Clinic.Example:443/"), "https://clinic.example")
        XCTAssertEqual(CheckinOrigin.serialize("https://clinic.example:8443/"), "https://clinic.example:8443")
        XCTAssertEqual(CheckinOrigin.serialize("http://127.0.0.1:3010"), "http://127.0.0.1:3010")
        XCTAssertEqual(CheckinOrigin.serialize(URL(string: "https://clinic.example/")!), "https://clinic.example")
        XCTAssertEqual(CheckinOrigin.serialize("android:apk-key-hash:abc_-123"), "android:apk-key-hash:abc_-123")
    }

    // An iOS provider gets the origin as a URL with a trailing slash; the
    // Wallet's transcript must still match the page's.
    func testWalletGivenURLOriginMatchesVerifierTranscript() throws {
        let req = request()
        let made = try CheckinVerifier.makeRequest(smartRequest: req)
        let (parsed, assembler) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: URL(string: "https://clinic.example/")!)
        XCTAssertEqual(assembler.origin, "https://clinic.example")
        let reply = try assembler.reply(smartResponse: patientResponse(parsed.smartRequest),
                                        issuerKey: P256.Signing.PrivateKey(), deviceKey: P256.Signing.PrivateKey())
        let opened = try CheckinVerifier.openResponse(
            retainedState: made.retainedState, origin: "https://clinic.example", dcapiResponseBase64Url: reply)
        XCTAssertTrue(opened.warnings.isEmpty, "\(opened.warnings)")
    }

    // [WRS-4] With no chain supplied, issuerAuth carries a self-signed
    // certificate for the issuer key, and a strict verifier finds the key there.
    func testWalletMintsIssuerCertificate() throws {
        let req = request()
        let made = try CheckinVerifier.makeRequest(smartRequest: req)
        let (parsed, assembler) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: "https://clinic.example")
        let issuer = P256.Signing.PrivateKey()
        let reply = try assembler.reply(smartResponse: patientResponse(parsed.smartRequest),
                                        issuerKey: issuer, deviceKey: P256.Signing.PrivateKey())
        // No trusted keys: the Verifier uses the x5chain leaf.
        let opened = try CheckinVerifier.openResponse(
            retainedState: made.retainedState, origin: "https://clinic.example", dcapiResponseBase64Url: reply)
        XCTAssertTrue(opened.issuerSignatureValid)
        XCTAssertTrue(opened.deviceSignatureValid)
        XCTAssertTrue(opened.valueDigestMatches)
        XCTAssertTrue(opened.allChecksPass, "\(opened.warnings) \(opened.crossCheck.report)")
        XCTAssertEqual(opened.issuerCertificateChain.count, 1)
        XCTAssertEqual(X509Helper.p256PublicKey(fromCertificate: opened.issuerCertificateChain[0])?.rawRepresentation,
                       issuer.publicKey.rawRepresentation)
        // [WRS-3] validity: signed == validFrom, whole seconds, later validUntil.
        let vi = try XCTUnwrap(opened.validityInfo)
        XCTAssertEqual(vi.signed, vi.validFrom)
        XCTAssertEqual(vi.signed.timeIntervalSince1970, vi.signed.timeIntervalSince1970.rounded(.down))
        XCTAssertGreaterThan(vi.validUntil, vi.validFrom)
    }

    // [RA-1] readerAuth's x5chain holds at least the signing certificate.
    func testReaderAuthCarriesCertificate() throws {
        let readerKey = P256.Signing.PrivateKey()
        let made = try CheckinVerifier.makeRequest(smartRequest: request(), readerSigningKey: readerKey, origin: "https://clinic.example")
        let (parsed, _) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: "https://clinic.example")
        let ra = try XCTUnwrap(parsed.readerAuth)
        XCTAssertNil(ra.payload)
        let chain = ra.unprotected.first { if case .unsigned(33) = $0.key { return true } else { return false } }?.value
        guard case .byteString(let der)? = chain else { return XCTFail("x5chain missing") }
        XCTAssertEqual(X509Helper.p256PublicKey(fromCertificate: der)?.rawRepresentation, readerKey.publicKey.rawRepresentation)
    }

    // [SEL-9] Unknown kinds reach the host as unsupported items, not errors.
    func testUnsupportedItemsReachTheHost() throws {
        let made = try CheckinVerifier.makeRequest(smartRequest: request())
        let (parsed, _) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: "https://clinic.example")
        XCTAssertEqual(Array(parsed.unsupportedItems.keys), ["odd"])
        XCTAssertTrue(parsed.warnings.isEmpty, "\(parsed.warnings)")
    }

    // [RCV-0] The Wallet won't send what a Verifier would disregard, but an
    // all-declined response is a normal answer ([HOLD-4]).
    func testWalletProducerCheck() throws {
        let req = request()
        let made = try CheckinVerifier.makeRequest(smartRequest: req)
        let (_, assembler) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: "https://clinic.example")
        let missingRow = SmartHealthCheckinResponse(requestId: req.id, artifacts: [],
                                                    requestStatus: [.init(item: "patient", status: .declined)])
        XCTAssertThrowsError(try assembler.reply(smartResponse: missingRow,
                                                 issuerKey: P256.Signing.PrivateKey(), deviceKey: P256.Signing.PrivateKey()))
        let allDeclined = SmartHealthCheckinResponse(requestId: req.id, artifacts: [],
                                                     requestStatus: req.items.map { .init(item: $0.id, status: .declined) })
        let reply = try assembler.reply(smartResponse: allDeclined,
                                        issuerKey: P256.Signing.PrivateKey(), deviceKey: P256.Signing.PrivateKey())
        let opened = try CheckinVerifier.openResponse(
            retainedState: made.retainedState, origin: "https://clinic.example", dcapiResponseBase64Url: reply)
        XCTAssertEqual(opened.crossCheck.itemOutcomes["patient"], .status(.declined))
        XCTAssertTrue(opened.warnings.isEmpty)
    }

    // [VRS-3] The wrong origin still fails: it's the one crypto check that's fatal.
    func testWrongOriginStillFails() throws {
        let req = request()
        let made = try CheckinVerifier.makeRequest(smartRequest: req)
        let (parsed, assembler) = try CheckinWallet.handleRequest(
            deviceRequestBase64Url: made.deviceRequestBase64Url,
            encryptionInfoBase64Url: made.encryptionInfoBase64Url,
            origin: "https://clinic.example/")
        let reply = try assembler.reply(smartResponse: patientResponse(parsed.smartRequest),
                                        issuerKey: P256.Signing.PrivateKey(), deviceKey: P256.Signing.PrivateKey())
        XCTAssertThrowsError(try CheckinVerifier.openResponse(
            retainedState: made.retainedState, origin: "https://other.example", dcapiResponseBase64Url: reply))
    }
}
