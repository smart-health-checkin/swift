// SPDX-License-Identifier: MIT
//
// DeviceResponse: the wallet→verifier message.
//
//   DeviceResponse = {
//     "version": "1.0",
//     "documents": [Document, ...],
//     "status": uint
//   }
//
//   Document = {
//     "docType":      "org.smarthealthit.checkin.1",
//     "issuerSigned": IssuerSigned,
//     "deviceSigned": DeviceSigned
//   }
//
//   IssuerSigned = {
//     "nameSpaces": { <namespace>: [Tag(24, bstr .cbor IssuerSignedItem), ...] },
//     "issuerAuth": COSE_Sign1               (attached payload, alg ES256)
//   }
//
//   The COSE payload of issuerAuth is `Tag(24, bstr .cbor MSO)` per RFC 9052
//   semantics for an attached signature over the tag-24-wrapped MSO.
//
//   DeviceSigned = {
//     "nameSpaces": Tag(24, bstr .cbor {}),  -- empty map by default
//     "deviceAuth": { "deviceSignature": COSE_Sign1 (detached payload, ES256) }
//   }
//
//   The deviceSignature signs (detached) the DeviceAuthentication bytes:
//   DeviceAuthentication = Tag(24, bstr .cbor [
//     "DeviceAuthentication",
//     SessionTranscript,
//     docType,
//     <deviceSigned.nameSpaces tag-24 bytes verbatim>
//   ])

import Foundation
import Crypto
import SmartHealthCheckinCBOR

// MARK: - IssuerSignedItem and MSO

public struct IssuerSignedItem: Sendable, Equatable {
    public var digestID: UInt64
    public var random: Data
    public var elementIdentifier: String
    public var elementValue: CBOR

    public init(digestID: UInt64, random: Data, elementIdentifier: String, elementValue: CBOR) {
        self.digestID = digestID; self.random = random
        self.elementIdentifier = elementIdentifier; self.elementValue = elementValue
    }

    public func toCBOR() -> CBOR {
        return .map([
            .init(key: .textString("digestID"),          value: .unsigned(digestID)),
            .init(key: .textString("random"),            value: .byteString(random)),
            .init(key: .textString("elementIdentifier"), value: .textString(elementIdentifier)),
            .init(key: .textString("elementValue"),      value: elementValue),
        ])
    }

    public static func fromCBOR(_ v: CBOR) throws -> IssuerSignedItem {
        guard case .map(let entries) = v else { throw DeviceResponseError.malformedItem }
        var digestID: UInt64?, random: Data?, elementIdentifier: String?, elementValue: CBOR?
        for e in entries {
            guard case .textString(let k) = e.key else { continue }
            switch k {
            case "digestID":          if case .unsigned(let n) = e.value { digestID = n }
            case "random":            if case .byteString(let d) = e.value { random = d }
            case "elementIdentifier": if case .textString(let s) = e.value { elementIdentifier = s }
            case "elementValue":      elementValue = e.value
            default: break
            }
        }
        guard let digestID = digestID, let random = random,
              let elementIdentifier = elementIdentifier, let elementValue = elementValue else {
            throw DeviceResponseError.malformedItem
        }
        return IssuerSignedItem(digestID: digestID, random: random,
                                elementIdentifier: elementIdentifier, elementValue: elementValue)
    }
}

public struct MobileSecurityObject: Sendable, Equatable {
    public var version: String
    public var digestAlgorithm: String
    /// namespace -> (digestID -> SHA-256 digest bytes)
    public var valueDigests: [(namespace: String, digests: [(id: UInt64, digest: Data)])]
    public var deviceKey: CBOR
    public var docType: String
    public var validityInfo: ValidityInfo

    public struct ValidityInfo: Sendable, Equatable {
        public var signed: Date
        public var validFrom: Date
        public var validUntil: Date
        public init(signed: Date, validFrom: Date, validUntil: Date) {
            self.signed = signed; self.validFrom = validFrom; self.validUntil = validUntil
        }
    }

    public init(version: String = "1.0", digestAlgorithm: String = "SHA-256",
                valueDigests: [(namespace: String, digests: [(id: UInt64, digest: Data)])],
                deviceKey: CBOR, docType: String, validityInfo: ValidityInfo) {
        self.version = version; self.digestAlgorithm = digestAlgorithm
        self.valueDigests = valueDigests; self.deviceKey = deviceKey
        self.docType = docType; self.validityInfo = validityInfo
    }

    public static func == (lhs: MobileSecurityObject, rhs: MobileSecurityObject) -> Bool {
        guard lhs.version == rhs.version, lhs.digestAlgorithm == rhs.digestAlgorithm,
              lhs.deviceKey == rhs.deviceKey, lhs.docType == rhs.docType,
              lhs.validityInfo == rhs.validityInfo,
              lhs.valueDigests.count == rhs.valueDigests.count
        else { return false }
        for (i, ns) in lhs.valueDigests.enumerated() {
            let other = rhs.valueDigests[i]
            if ns.namespace != other.namespace || ns.digests.count != other.digests.count { return false }
            for (j, d) in ns.digests.enumerated() {
                if d.id != other.digests[j].id || d.digest != other.digests[j].digest { return false }
            }
        }
        return true
    }

    public func toCBOR() -> CBOR {
        let validity = CBOR.map([
            .init(key: .textString("signed"),     value: .tagged(0, .textString(Self.iso8601(validityInfo.signed)))),
            .init(key: .textString("validFrom"),  value: .tagged(0, .textString(Self.iso8601(validityInfo.validFrom)))),
            .init(key: .textString("validUntil"), value: .tagged(0, .textString(Self.iso8601(validityInfo.validUntil)))),
        ])
        let valueDigestsCBOR = CBOR.map(valueDigests.map { ns in
            CBORMapEntry(key: .textString(ns.namespace), value: .map(ns.digests.map {
                .init(key: .unsigned($0.id), value: .byteString($0.digest))
            }))
        })
        let deviceKeyInfo = CBOR.map([
            .init(key: .textString("deviceKey"), value: deviceKey),
        ])
        return .map([
            .init(key: .textString("version"),         value: .textString(version)),
            .init(key: .textString("digestAlgorithm"), value: .textString(digestAlgorithm)),
            .init(key: .textString("valueDigests"),    value: valueDigestsCBOR),
            .init(key: .textString("deviceKeyInfo"),   value: deviceKeyInfo),
            .init(key: .textString("docType"),         value: .textString(docType)),
            .init(key: .textString("validityInfo"),    value: validity),
        ])
    }

    public static func fromCBOR(_ v: CBOR) throws -> MobileSecurityObject {
        guard case .map(let entries) = v else { throw DeviceResponseError.malformedMSO }
        var version: String?, digestAlgorithm: String?, docType: String?
        var valueDigestsRaw: CBOR?, deviceKeyInfoRaw: CBOR?, validityInfoRaw: CBOR?
        for e in entries {
            guard case .textString(let k) = e.key else { continue }
            switch k {
            case "version":         if case .textString(let s) = e.value { version = s }
            case "digestAlgorithm": if case .textString(let s) = e.value { digestAlgorithm = s }
            case "docType":         if case .textString(let s) = e.value { docType = s }
            case "valueDigests":    valueDigestsRaw = e.value
            case "deviceKeyInfo":   deviceKeyInfoRaw = e.value
            case "validityInfo":    validityInfoRaw = e.value
            default: break
            }
        }
        guard let version = version, let digestAlgorithm = digestAlgorithm, let docType = docType,
              let valueDigestsRaw = valueDigestsRaw, let deviceKeyInfoRaw = deviceKeyInfoRaw,
              let validityInfoRaw = validityInfoRaw else {
            throw DeviceResponseError.malformedMSO
        }
        // valueDigests
        guard case .map(let nsEntries) = valueDigestsRaw else { throw DeviceResponseError.malformedMSO }
        var valueDigests: [(namespace: String, digests: [(id: UInt64, digest: Data)])] = []
        for e in nsEntries {
            guard case .textString(let ns) = e.key, case .map(let dEntries) = e.value else {
                throw DeviceResponseError.malformedMSO
            }
            var ds: [(id: UInt64, digest: Data)] = []
            for de in dEntries {
                guard case .unsigned(let id) = de.key, case .byteString(let d) = de.value else {
                    throw DeviceResponseError.malformedMSO
                }
                ds.append((id, d))
            }
            valueDigests.append((ns, ds))
        }
        // deviceKey
        guard case .map(let dki) = deviceKeyInfoRaw,
              let dkEntry = dki.first(where: { (entry) -> Bool in
                  if case .textString(let s) = entry.key { return s == "deviceKey" } else { return false }
              }) else {
            throw DeviceResponseError.malformedMSO
        }
        let deviceKey = dkEntry.value
        // validityInfo
        guard case .map(let viEntries) = validityInfoRaw else { throw DeviceResponseError.malformedMSO }
        func parseTaggedDate(_ v: CBOR) throws -> Date {
            if case .tagged(0, let inner) = v, case .textString(let s) = inner {
                if let d = iso8601Parse(s) { return d }
            }
            throw DeviceResponseError.malformedMSO
        }
        var signed: Date?, validFrom: Date?, validUntil: Date?
        for e in viEntries {
            guard case .textString(let k) = e.key else { continue }
            switch k {
            case "signed":     signed = try parseTaggedDate(e.value)
            case "validFrom":  validFrom = try parseTaggedDate(e.value)
            case "validUntil": validUntil = try parseTaggedDate(e.value)
            default: break
            }
        }
        guard let signed = signed, let validFrom = validFrom, let validUntil = validUntil else {
            throw DeviceResponseError.malformedMSO
        }
        return MobileSecurityObject(
            version: version, digestAlgorithm: digestAlgorithm,
            valueDigests: valueDigests, deviceKey: deviceKey, docType: docType,
            validityInfo: .init(signed: signed, validFrom: validFrom, validUntil: validUntil)
        )
    }

    static let iso8601Formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
    static func iso8601(_ d: Date) -> String { iso8601Formatter.string(from: d) }
}

func iso8601Parse(_ s: String) -> Date? {
    if let d = MobileSecurityObject.iso8601Formatter.date(from: s) { return d }
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: s)
}

// MARK: - DeviceAuthentication payload helpers

public enum DeviceAuthentication {
    /// Build the bytes the wallet signs in `deviceSignature` (and the verifier
    /// re-builds during verification). The fourth element MUST be the EXACT
    /// `deviceSigned.nameSpaces` tag-24 bytes that appear in the response — do
    /// NOT hardcode `{}` if anything else was sent.
    public static func bytes(
        sessionTranscript: Data,
        docType: String,
        deviceNamespacesTag24Bytes: Data
    ) -> Data {
        let inner = RawCBORBuilder.arrayBytes([
            RawCBORBuilder.textString("DeviceAuthentication"),
            sessionTranscript,            // already CBOR
            RawCBORBuilder.textString(docType),
            deviceNamespacesTag24Bytes,   // already CBOR (Tag(24, bstr))
        ])
        return RawCBORBuilder.tag24(inner: inner)
    }
}

// MARK: - DeviceResponse model

public struct CheckinDeviceResponse: Sendable {
    public var version: String
    public var documents: [Document]
    public var status: UInt64
    /// Structural problems the parser stepped over, such as a document it
    /// couldn't read ([RCV-1]).
    public var warnings: [CheckinWarning] = []

    public struct Document: Sendable {
        public var docType: String
        public var issuerSigned: IssuerSigned
        public var deviceSigned: DeviceSigned
        public init(docType: String, issuerSigned: IssuerSigned, deviceSigned: DeviceSigned) {
            self.docType = docType; self.issuerSigned = issuerSigned; self.deviceSigned = deviceSigned
        }
    }

    public struct IssuerSigned: Sendable {
        /// namespace -> [(IssuerSignedItem, exact tag-24 bytes from source)]
        public var nameSpaces: [(namespace: String, items: [Item])]
        /// nil when absent or not a COSE_Sign1 (a receiver warns, [VRS-5]).
        public var issuerAuth: COSESign1?

        public struct Item: Sendable {
            public var item: IssuerSignedItem
            /// The exact bytes of the `Tag(24, bstr .cbor IssuerSignedItem)` wrapper
            /// as it appears on the wire. Used for digest verification.
            public var tag24Bytes: Data
            public init(item: IssuerSignedItem, tag24Bytes: Data) {
                self.item = item; self.tag24Bytes = tag24Bytes
            }
        }

        public init(nameSpaces: [(namespace: String, items: [Item])], issuerAuth: COSESign1?) {
            self.nameSpaces = nameSpaces; self.issuerAuth = issuerAuth
        }
    }

    public struct DeviceSigned: Sendable {
        /// Decoded namespaces (typically empty `{}` for SMART Health Check-in).
        public var nameSpaces: CBOR
        /// Exact tag-24 byte slice for `nameSpaces` as received.
        public var nameSpacesTag24Bytes: Data
        /// nil when absent or not a COSE_Sign1 (a receiver warns, [VRS-7]).
        public var deviceSignature: COSESign1?

        public init(nameSpaces: CBOR, nameSpacesTag24Bytes: Data, deviceSignature: COSESign1?) {
            self.nameSpaces = nameSpaces
            self.nameSpacesTag24Bytes = nameSpacesTag24Bytes
            self.deviceSignature = deviceSignature
        }
    }

    public init(version: String = "1.0", documents: [Document], status: UInt64 = 0) {
        self.version = version; self.documents = documents; self.status = status
    }
}

public enum DeviceResponseError: Error, Equatable, Sendable {
    case malformed
    case malformedItem
    case malformedMSO
    case unsupportedVersion(String)
    case unexpectedDocType(String)
    case unexpectedNamespace(String)
    case missingItem(namespace: String, element: String)
    case digestMismatch
    case missingDigestEntry
    case mdocVersionMismatch
    case msoDocTypeMismatch(expected: String, actual: String)
    case validityInfoOutOfRange
    /// The response element's value is not a text string ([VRS-8]).
    case elementNotText
}

// MARK: - Builder

public enum DeviceResponseBuilder {

    public struct Options {
        public var docType: String
        public var namespace: String
        public var element: String
        public init(docType: String, namespace: String, element: String) {
            self.docType = docType; self.namespace = namespace; self.element = element
        }
    }

    public struct BuildResult {
        /// Encoded `DeviceResponse` CBOR bytes — the plaintext that goes into HPKE.
        public var deviceResponseBytes: Data
    }

    /// Build an mdoc DeviceResponse for the SMART Health Check-in flow.
    ///
    /// - Parameters:
    ///   - smartResponseJSON: the SMART response JSON (UTF-8 text).
    ///   - issuerKey: ES256 private key that issuer-signs the MSO.
    ///   - deviceKey: ES256 private key that signs `DeviceAuthentication`. Its
    ///     public counterpart is recorded in the MSO's `deviceKey`.
    ///   - sessionTranscript: bytes computed by §8.3.
    ///   - issuerCertificateChain: chain to attach as COSE header label 33
    ///     (`x5chain`), leaf first. When empty, a self-signed certificate for
    ///     `issuerKey` is minted ([WRS-4]).
    public static func build(
        smartResponseJSON: Data,
        issuerKey: P256.Signing.PrivateKey,
        deviceKey: P256.Signing.PrivateKey,
        sessionTranscript: Data,
        options: Options,
        validityInfo: MobileSecurityObject.ValidityInfo? = nil,
        issuerCertificateChain: [Data] = []
    ) throws -> Data {
        // 1. IssuerSignedItem with the SMART response JSON as a CBOR text string.
        let item = IssuerSignedItem(
            digestID: 0,
            random: randomBytes(16),
            elementIdentifier: options.element,
            elementValue: .textString(String(decoding: smartResponseJSON, as: UTF8.self))
        )
        let itemInnerBytes = CBOREncoder.encode(item.toCBOR())
        let itemTag24Bytes = RawCBORBuilder.tag24(inner: itemInnerBytes)
        let valueDigest = Data(SHA256.hash(data: itemTag24Bytes))

        // 2. Build MSO and sign it as the COSE_Sign1 *attached* payload of
        //    `Tag(24, bstr .cbor MSO)` per the rubber-duck guidance.
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let validity = validityInfo ?? .init(
            signed: now,
            validFrom: now,
            validUntil: now.addingTimeInterval(60 * 60) // 1 hour
        )
        let deviceKeyCOSE = COSEKey.encodeP256(publicKey: deviceKey.publicKey)
        let mso = MobileSecurityObject(
            valueDigests: [(options.namespace, [(0, valueDigest)])],
            deviceKey: deviceKeyCOSE,
            docType: options.docType,
            validityInfo: validity
        )
        let msoBytes = CBOREncoder.encode(mso.toCBOR())
        let msoTag24Bytes = RawCBORBuilder.tag24(inner: msoBytes)
        // Attached: payload = tag-24-wrapped MSO bytes.
        let issuerProtected = COSESign1Signer.es256ProtectedHeader()
        var issuerUnprotected: [CBORMapEntry] = []
        // [WRS-4] x5chain carries the certificate for the issuer key. With none
        // supplied, the Wallet self-signs one for this key (§7 allows it).
        var issuerCertificateChain = issuerCertificateChain
        if issuerCertificateChain.isEmpty {
            issuerCertificateChain = [try X509Helper.selfSignedCertificate(
                for: issuerKey, commonName: "SMART Health Check-in Wallet",
                notBefore: validity.validFrom, notAfter: validity.validUntil)]
        }
        if !issuerCertificateChain.isEmpty {
            // COSE header label 33 (x5chain): single bstr if one cert, otherwise
            // an array of bstrs.
            if issuerCertificateChain.count == 1 {
                issuerUnprotected.append(.init(key: .int(33), value: .byteString(issuerCertificateChain[0])))
            } else {
                issuerUnprotected.append(.init(key: .int(33),
                    value: .array(issuerCertificateChain.map { .byteString($0) })))
            }
        }
        let issuerAuth = try COSESign1Signer.sign(
            payload: msoTag24Bytes,
            attached: true,
            privateKey: issuerKey,
            protectedBytes: issuerProtected,
            unprotected: issuerUnprotected
        )

        // 3. Build deviceSigned. nameSpaces is empty {} wrapped in tag-24.
        let emptyMap = CBOREncoder.encode(.map([]))
        let deviceNamespacesTag24Bytes = RawCBORBuilder.tag24(inner: emptyMap)
        let deviceAuthBytes = DeviceAuthentication.bytes(
            sessionTranscript: sessionTranscript,
            docType: options.docType,
            deviceNamespacesTag24Bytes: deviceNamespacesTag24Bytes
        )
        let deviceProtected = COSESign1Signer.es256ProtectedHeader()
        // ISO 18013-5: the device signature's payload is detached (null);
        // the verifier rebuilds DeviceAuthenticationBytes from its own
        // session transcript.
        let deviceSig = try COSESign1Signer.sign(
            payload: deviceAuthBytes,
            attached: false,
            privateKey: deviceKey,
            protectedBytes: deviceProtected
        )

        // 4. Build DeviceResponse map.
        let issuerSigned = CBOR.map([
            .init(key: .textString("nameSpaces"), value: .map([
                .init(key: .textString(options.namespace), value: .array([
                    .tagged(24, .byteString(itemInnerBytes))
                ]))
            ])),
            .init(key: .textString("issuerAuth"), value: issuerAuth.asCBOR()),
        ])
        let deviceSigned = CBOR.map([
            .init(key: .textString("nameSpaces"), value: .tagged(24, .byteString(emptyMap))),
            .init(key: .textString("deviceAuth"), value: .map([
                .init(key: .textString("deviceSignature"), value: deviceSig.asCBOR()),
            ])),
        ])
        let document = CBOR.map([
            .init(key: .textString("docType"),      value: .textString(options.docType)),
            .init(key: .textString("issuerSigned"), value: issuerSigned),
            .init(key: .textString("deviceSigned"), value: deviceSigned),
        ])
        let deviceResponse = CBOR.map([
            .init(key: .textString("version"),   value: .textString("1.0")),
            .init(key: .textString("documents"), value: .array([document])),
            .init(key: .textString("status"),    value: .unsigned(0)),
        ])
        return CBOREncoder.encode(deviceResponse)
    }

    static func randomBytes(_ count: Int) -> Data {
        var d = Data(count: count)
        d.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            for i in 0..<count { base.advanced(by: i).storeBytes(of: UInt8.random(in: 0...255), as: UInt8.self) }
        }
        return d
    }
}

// MARK: - Parser

public enum DeviceResponseParser {
    /// Decode a DeviceResponse as a Verifier receives it. Fails only if the
    /// bytes aren't a CBOR map. Documents, items, and COSE structures that
    /// can't be read are skipped or left nil and noted in `warnings`; the
    /// validator decides what's fatal ([VRS-4]..[VRS-8]).
    public static func parse(_ data: Data) throws -> CheckinDeviceResponse {
        let decoded = try CBORDecoder.lenient.decodeWithSlices(data)
        guard case .map(let entries) = decoded.value else { throw DeviceResponseError.malformed }
        var version = ""
        var documentsRaw: [CBOR] = []
        var status: UInt64 = 0
        var warnings: [CheckinWarning] = []
        for e in entries {
            guard case .textString(let k) = e.key else { continue }
            switch k {
            case "version":   if case .textString(let s) = e.value { version = s }
            case "documents": if case .array(let xs) = e.value { documentsRaw = xs }
            case "status":    if case .unsigned(let n) = e.value { status = n }
            default: break
            }
        }

        var docs: [CheckinDeviceResponse.Document] = []
        for (di, doc) in documentsRaw.enumerated() {
            do {
                docs.append(try parseDocument(doc, at: di, in: decoded))
            } catch {
                warnings.append(.init("documents", "skipped document \(di): \(error)"))
            }
        }
        var out = CheckinDeviceResponse(version: version, documents: docs, status: status)
        out.warnings = warnings
        return out
    }

    static func parseDocument(_ doc: CBOR, at di: Int, in decoded: CBORDecoder.DecodedCBOR) throws -> CheckinDeviceResponse.Document {
        guard case .map(let docEntries) = doc else { throw DeviceResponseError.malformed }
        var docType: String?
        var issuerSigned: CBOR?, deviceSigned: CBOR?
        for e in docEntries {
            guard case .textString(let k) = e.key else { continue }
            switch k {
            case "docType":      if case .textString(let s) = e.value { docType = s }
            case "issuerSigned": issuerSigned = e.value
            case "deviceSigned": deviceSigned = e.value
            default: break
            }
        }
        guard let docType = docType, case .map(let isEntries)? = issuerSigned else { throw DeviceResponseError.malformed }
        var issuerAuth: COSESign1?
        var nameSpaces: [(namespace: String, items: [CheckinDeviceResponse.IssuerSigned.Item])] = []
        for e in isEntries {
            guard case .textString(let k) = e.key else { continue }
            if k == "issuerAuth" {
                issuerAuth = try? COSESign1.from(e.value)
            } else if k == "nameSpaces", case .map(let nsEntries) = e.value {
                for ne in nsEntries {
                    guard case .textString(let nsName) = ne.key, case .array(let arr) = ne.value else { continue }
                    var items: [CheckinDeviceResponse.IssuerSigned.Item] = []
                    for (ii, av) in arr.enumerated() {
                        guard case let .tagged(24, .byteString(inner)) = av,
                              let innerValue = try? CBORDecoder.lenient.decode(inner),
                              let item = try? IssuerSignedItem.fromCBOR(innerValue) else { continue }
                        // The EXACT outer tag-24 byte slice from the source, for the digest ([ENC-2]).
                        let slice = try decoded.slice(at: [
                            .key(.textString("documents")), .index(di),
                            .key(.textString("issuerSigned")), .key(.textString("nameSpaces")),
                            .key(.textString(nsName)), .index(ii),
                        ]).source
                        items.append(.init(item: item, tag24Bytes: slice))
                    }
                    nameSpaces.append((nsName, items))
                }
            }
        }
        // DeviceSigned: any problem here only affects the device signature check.
        var dnsValue: CBOR = .map([])
        var dnsTag24Bytes = Data()
        var deviceSig: COSESign1?
        if case .map(let dsEntries)? = deviceSigned {
            for e in dsEntries {
                guard case .textString(let k) = e.key else { continue }
                if k == "nameSpaces", case let .tagged(24, .byteString(inner)) = e.value {
                    dnsValue = (try? CBORDecoder.lenient.decode(inner)) ?? .map([])
                    dnsTag24Bytes = (try? decoded.slice(at: [
                        .key(.textString("documents")), .index(di),
                        .key(.textString("deviceSigned")), .key(.textString("nameSpaces")),
                    ]).source) ?? Data()
                }
                if k == "deviceAuth", case .map(let daEntries) = e.value,
                   let sig = daEntries.first(where: { if case .textString("deviceSignature") = $0.key { return true } else { return false } }) {
                    deviceSig = try? COSESign1.from(sig.value)
                }
            }
        }
        return .init(
            docType: docType,
            issuerSigned: .init(nameSpaces: nameSpaces, issuerAuth: issuerAuth),
            deviceSigned: .init(nameSpaces: dnsValue, nameSpacesTag24Bytes: dnsTag24Bytes, deviceSignature: deviceSig)
        )
    }
}

// MARK: - Verifier-side validation

public struct CheckinDeviceResponseValidation: Sendable {
    public var docType: String
    public var smartResponseJSON: Data
    public var issuerSignatureValid: Bool
    public var deviceSignatureValid: Bool
    public var digestMatch: Bool
    /// nil when the MSO has no readable validityInfo (a warning).
    public var validityInfo: MobileSecurityObject.ValidityInfo?
    public var issuerCertificateChain: [Data]
    /// Everything that failed but doesn't stop the Verifier ([RCV-1]). Empty
    /// when every signature, digest, and MSO field checks out.
    public var warnings: [CheckinWarning]
}

public enum DeviceResponseValidator {

    public struct Options {
        public var docType: String
        public var namespace: String
        public var element: String
        /// Optional issuer trust check. If nil, the issuer signature is checked
        /// against the leaf certificate in `x5chain` (§7: signatures show the
        /// mdoc is intact and well formed, not who issued it).
        public var trustedIssuerKeys: [P256.Signing.PublicKey]?
        /// The time to check the MSO validity window against ([VRS-10]).
        public var now: Date
        /// Clock difference tolerated around the validity window.
        public var clockSkew: TimeInterval
        public init(docType: String, namespace: String, element: String,
                    trustedIssuerKeys: [P256.Signing.PublicKey]? = nil,
                    now: Date = Date(), clockSkew: TimeInterval = 300) {
            self.docType = docType; self.namespace = namespace; self.element = element
            self.trustedIssuerKeys = trustedIssuerKeys
            self.now = now; self.clockSkew = clockSkew
        }
    }

    /// Validate a DeviceResponse as a Verifier (§8.5). Throws only where §8.5
    /// says **fail**: no document with `options.docType` ([VRS-4]), or no
    /// response element with a text value ([VRS-8]). Every other problem —
    /// signatures, digests, MSO fields, validity, versions, status — is
    /// reported in `warnings` and the boolean fields ([VRS-4]..[VRS-7], [VRS-10]).
    public static func validate(
        _ response: CheckinDeviceResponse,
        sessionTranscript: Data,
        options: Options
    ) throws -> CheckinDeviceResponseValidation {
        var warnings = response.warnings
        if response.version != "1.0" {
            warnings.append(.init("device-response-version", "DeviceResponse version is \"\(response.version)\", not \"1.0\""))
        }
        if response.status != 0 {
            warnings.append(.init("device-response-status", "DeviceResponse status is \(response.status), not 0"))
        }
        let matching = response.documents.filter { $0.docType == options.docType }
        guard let doc = matching.first else {
            throw DeviceResponseError.unexpectedDocType(response.documents.first?.docType ?? "<none>")
        }
        if response.documents.count > 1 {
            warnings.append(.init("documents", "\(response.documents.count) documents in the DeviceResponse; using the first \(options.docType)"))
        }

        // [VRS-8] The response element must be present with a text value.
        guard let smartItem = doc.issuerSigned.nameSpaces
            .first(where: { $0.namespace == options.namespace })?
            .items.first(where: { $0.item.elementIdentifier == options.element }) else {
            throw DeviceResponseError.missingItem(namespace: options.namespace, element: options.element)
        }
        guard case .textString(let smartJSON) = smartItem.item.elementValue else {
            throw DeviceResponseError.elementNotText
        }

        // [VRS-5] issuerAuth.
        var issuerSignatureValid = false
        var issuerCertificateChain: [Data] = []
        var msoMap: [CBORMapEntry]?
        if let issuerAuth = doc.issuerSigned.issuerAuth {
            for e in issuerAuth.unprotected {
                if case .unsigned(33) = e.key { issuerCertificateChain = extractCertChain(e.value) }
            }
            var candidateKeys: [P256.Signing.PublicKey] = options.trustedIssuerKeys ?? []
            if candidateKeys.isEmpty, let leaf = issuerCertificateChain.first, let key = leafSubjectPublicKey(leaf) {
                candidateKeys.append(key)
            }
            if candidateKeys.isEmpty {
                warnings.append(.init("issuer-signature", "no issuer key: x5chain is missing or unreadable"))
            } else if let algWarning = algWarning(issuerAuth.protectedBytes, "issuerAuth") {
                warnings.append(algWarning)
                warnings.append(.init("issuer-signature", "issuerAuth not verified: unsupported algorithm"))
            } else {
                for k in candidateKeys where (try? COSESign1Signer.verify(issuerAuth, publicKey: k)) != nil {
                    issuerSignatureValid = true; break
                }
                if !issuerSignatureValid { warnings.append(.init("issuer-signature", "issuerAuth signature does not verify")) }
            }
            if let payload = issuerAuth.payload, let p = try? CBORDecoder.lenient.decode(payload) {
                var msoValue: CBOR? = nil
                if case let .tagged(24, .byteString(inner)) = p { msoValue = try? CBORDecoder.lenient.decode(inner) }
                else if case .map = p { msoValue = p }
                if case .map(let m)? = msoValue { msoMap = m }
            }
        } else {
            warnings.append(.init("issuer-signature", "issuerAuth is missing or not a COSE_Sign1"))
        }

        // MSO fields, read one by one so each problem is its own warning.
        func field(_ name: String) -> CBOR? {
            msoMap?.first(where: { if case .textString(name) = $0.key { return true } else { return false } })?.value
        }
        var validityInfo: MobileSecurityObject.ValidityInfo?
        var digestMatch = false
        var deviceKey: P256.Signing.PublicKey?
        if msoMap == nil {
            warnings.append(.init("mso", "issuerAuth carries no readable MobileSecurityObject"))
        } else {
            if case .textString(let v)? = field("version"), v == "1.0" {} else {
                warnings.append(.init("mso-version", "MSO version is not \"1.0\""))
            }
            if case .textString(let dt)? = field("docType"), dt == doc.docType {} else {
                warnings.append(.init("mso-doc-type", "MSO docType doesn't match the document's"))
            }
            // [VRS-10] validity window.
            if let vi = parseValidityInfo(field("validityInfo")) {
                validityInfo = vi
                if options.now < vi.validFrom.addingTimeInterval(-options.clockSkew)
                    || options.now > vi.validUntil.addingTimeInterval(options.clockSkew) {
                    warnings.append(.init("mso-validity", "the MSO is not valid at \(MobileSecurityObject.iso8601(options.now))"))
                }
            } else {
                warnings.append(.init("mso-validity-info", "MSO has no readable validityInfo"))
            }
            // [VRS-6] value digest.
            if case .textString(let alg)? = field("digestAlgorithm"), alg == "SHA-256" {
                var expected: Data?
                if case .map(let nsEntries)? = field("valueDigests"),
                   case .map(let dEntries)? = nsEntries.first(where: { if case .textString(options.namespace) = $0.key { return true } else { return false } })?.value,
                   case .byteString(let d)? = dEntries.first(where: { if case .unsigned(smartItem.item.digestID) = $0.key { return true } else { return false } })?.value {
                    expected = d
                }
                if let expected = expected {
                    digestMatch = Data(SHA256.hash(data: smartItem.tag24Bytes)) == expected
                    if !digestMatch { warnings.append(.init("digest", "the response element's digest doesn't match the MSO")) }
                } else {
                    warnings.append(.init("digest", "the MSO has no digest for digestID \(smartItem.item.digestID)"))
                }
            } else {
                warnings.append(.init("digest-algorithm", "MSO digestAlgorithm is not SHA-256; digest not checked"))
            }
            if case .map(let dki)? = field("deviceKeyInfo"),
               let dk = dki.first(where: { if case .textString("deviceKey") = $0.key { return true } else { return false } })?.value {
                deviceKey = try? COSEKey.decodeP256(dk).asSigningKey()
            }
        }

        // [VRS-7] device signature over the rebuilt DeviceAuthenticationBytes.
        var deviceSignatureValid = false
        if let sig = doc.deviceSigned.deviceSignature, let key = deviceKey {
            let devAuthBytes = DeviceAuthentication.bytes(
                sessionTranscript: sessionTranscript,
                docType: options.docType,
                deviceNamespacesTag24Bytes: doc.deviceSigned.nameSpacesTag24Bytes
            )
            if let algWarning = algWarning(sig.protectedBytes, "deviceSignature") {
                warnings.append(algWarning)
            } else if let attached = sig.payload, attached != devAuthBytes {
                // An attached payload must equal the rebuilt bytes.
            } else {
                deviceSignatureValid = (try? COSESign1Signer.verify(sig, publicKey: key, detachedPayload: devAuthBytes)) != nil
            }
            if !deviceSignatureValid {
                warnings.append(.init("device-signature", "the device signature does not verify over this session's DeviceAuthentication"))
            }
        } else {
            warnings.append(.init("device-signature", doc.deviceSigned.deviceSignature == nil
                ? "deviceSignature is missing or not a COSE_Sign1" : "the MSO has no usable deviceKey"))
        }

        return .init(
            docType: doc.docType,
            smartResponseJSON: Data(smartJSON.utf8),
            issuerSignatureValid: issuerSignatureValid,
            deviceSignatureValid: deviceSignatureValid,
            digestMatch: digestMatch,
            validityInfo: validityInfo,
            issuerCertificateChain: issuerCertificateChain,
            warnings: warnings
        )
    }

    /// An `alg` warning when a protected header doesn't say ES256 ([ALG-2]).
    static func algWarning(_ protectedBytes: Data, _ what: String) -> CheckinWarning? {
        do { try COSESign1Signer.requireES256(in: protectedBytes); return nil }
        catch { return .init("alg", "\(what) doesn't use ES256 (\(error))") }
    }

    static func parseValidityInfo(_ v: CBOR?) -> MobileSecurityObject.ValidityInfo? {
        guard case .map(let entries)? = v else { return nil }
        func date(_ name: String) -> Date? {
            guard let e = entries.first(where: { if case .textString(name) = $0.key { return true } else { return false } }),
                  case .tagged(0, .textString(let s)) = e.value else { return nil }
            return iso8601Parse(s)
        }
        guard let signed = date("signed"), let from = date("validFrom"), let until = date("validUntil") else { return nil }
        return .init(signed: signed, validFrom: from, validUntil: until)
    }

    static func extractCertChain(_ v: CBOR) -> [Data] {
        switch v {
        case .byteString(let d): return [d]
        case .array(let xs): return xs.compactMap { if case .byteString(let d) = $0 { return d } else { return nil } }
        default: return []
        }
    }

    static func leafSubjectPublicKey(_ certDER: Data) -> P256.Signing.PublicKey? {
        X509Helper.p256PublicKey(fromCertificate: certDER)
    }
}
