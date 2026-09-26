// SPDX-License-Identifier: MIT
//
// High-level **Wallet** role: parse an incoming DeviceRequest, surface the
// SMART JSON request to the host UI for user consent, then assemble a
// signed+sealed `dcapiResponse` to hand back through the W3C DC API.
//
// The wallet owns:
//   * an issuer keypair (the credential issuer's signing key — typically rooted
//     in the wallet's provisioning flow; for testing the host can mint one)
//   * an mdoc device keypair (one per credential instance)
//   * the user's clinical content the wallet is willing to share
//
// The flow is two-stage so the host UI can show the parsed SMART request,
// gather user consent, and only then build the response.

import Foundation
@preconcurrency import Crypto
import SmartHealthCheckinModel
import SmartHealthCheckinCBOR
import SmartHealthCheckinMdoc

public enum CheckinWalletError: Error, Sendable {
    case malformedDeviceRequest(String)
    case missingSmartRequestCarrier
    case smartRequestInvalid(ValidationReport)
    /// encryptionInfo has no usable P-256 recipient key ([WRQ-7]).
    case noUsableEncryptionKey(String)
    /// The SMART response the host built isn't one a strict Verifier would
    /// accept whole: wrong requestId, a status row missing or doubled, or an
    /// Artifact it would disregard ([RSP-1]..[RSP-3], [ART-1], [ACC-2]).
    case responseNotConformant(CrossCheck)
}

public struct ParsedCheckinRequest {
    public let smartRequest: SmartHealthCheckinRequest
    public let smartRequestValidation: ValidationReport
    public let intentToRetain: Bool
    public let docType: String
    public let namespace: String
    public let element: String
    public let readerAuth: COSESign1?
    public let itemsRequestTag24Bytes: Data
    /// Problems that didn't stop the Wallet ([RCV-1]). Show or log them.
    public let warnings: [CheckinWarning]
    /// Items the Wallet must answer `unsupported`, keyed by item id, with why
    /// ([SEL-8], [SEL-9], [SEL-10], [FORM-1]).
    public let unsupportedItems: [String: String]
}

public struct WalletResponseAssembler {
    public let parsed: ParsedCheckinRequest
    public let encryptionInfoBase64Url: String
    public let origin: String

    /// Build the final base64url-encoded `dcapiResponse` to pass back through
    /// the DC API. The wallet host supplies:
    ///   - the SMART response model the user chose to release
    ///   - the credential's issuer signing key (P-256)
    ///   - the credential's device signing key (P-256)
    ///   - optional issuer certificate chain (DER bytes); by default a
    ///     self-signed certificate for `issuerKey` ([WRS-4])
    ///   - optional MSO validity window (defaults to now until an hour from now)
    public func reply(
        smartResponse: SmartHealthCheckinResponse,
        issuerKey: P256.Signing.PrivateKey,
        deviceKey: P256.Signing.PrivateKey,
        issuerCertificateChain: [Data] = [],
        validityInfo: MobileSecurityObject.ValidityInfo? = nil
    ) throws -> String {
        // A producer builds exactly what the spec describes ([RCV-0]): refuse to
        // send anything a Verifier would reject or partly disregard.
        let check = SmartHealthCheckinValidator.crossCheck(
            request: parsed.smartRequest, response: smartResponse
        )
        let unknownItems = check.itemOutcomes.values.contains { if case .unknown = $0 { return true } else { return false } }
        if check.report.hasErrors || !check.disregardedArtifacts.isEmpty || unknownItems {
            throw CheckinWalletError.responseNotConformant(check)
        }
        let smartJSON = smartResponse.toJSONData()

        // Decode encryptionInfo to get the recipient public key.
        let encInfoBytes = try Base64URL.decode(encryptionInfoBase64Url)
        let envelope = try EncryptionInfo.decodeLenient(encInfoBytes)
        let st = SessionTranscript.dcapi(
            encryptionInfoBase64Url: encryptionInfoBase64Url, origin: origin
        )

        // Build the inner DeviceResponse plaintext.
        let opts = DeviceResponseBuilder.Options(
            docType: parsed.docType,
            namespace: parsed.namespace,
            element: parsed.element
        )
        let plaintext = try DeviceResponseBuilder.build(
            smartResponseJSON: smartJSON,
            issuerKey: issuerKey,
            deviceKey: deviceKey,
            sessionTranscript: st,
            options: opts,
            validityInfo: validityInfo,
            issuerCertificateChain: issuerCertificateChain
        )

        // Seal with HPKE and wrap in the dcapi envelope.
        let sealed = try CheckinHPKE.seal(
            plaintext: plaintext, recipientPublicKey: envelope.recipientPublicKey, info: st
        )
        let envBytes = DCAPIResponse.encode(enc: sealed.enc, ciphertext: sealed.ciphertext)
        return Base64URL.encode(envBytes)
    }
}

public enum CheckinWallet {

    /// Parse a DeviceRequest from the W3C DC API call and return both the
    /// host-readable SMART request and an opaque assembler for the reply.
    ///
    /// Fails only where §8.4 says **fail** ([WRQ-1]): the request doesn't
    /// decode, has no DocRequest for this profile or no request text, the
    /// SMART request is invalid (§5), or encryptionInfo has no usable key.
    /// Everything else is in `parsed.warnings`.
    ///
    /// - Parameters:
    ///   - origin: the caller's origin as the platform reports it. Web origins
    ///     are serialized per [TR-2] (a platform URL such as `https://host/`
    ///     loses its trailing slash). Take it only from the platform ([TR-3]).
    ///   - protocol: the DC API request's `protocol`, if the host has it.
    ///
    /// The caller MUST let the Holder choose ([HOLD-1]) before invoking
    /// `assembler.reply(...)`.
    public static func handleRequest(
        deviceRequestBase64Url: String,
        encryptionInfoBase64Url: String,
        origin: String,
        protocol dcProtocol: String? = nil
    ) throws -> (parsed: ParsedCheckinRequest, assembler: WalletResponseAssembler) {
        var warnings: [CheckinWarning] = []
        if let p = dcProtocol, p != SmartHealthCheckinConstants.dcApiProtocol {
            warnings.append(.init("protocol", "the request's protocol is \"\(p)\", not \"\(SmartHealthCheckinConstants.dcApiProtocol)\" ([WRQ-2])"))
        }
        if Base64URL.isPadded(deviceRequestBase64Url) || Base64URL.isPadded(encryptionInfoBase64Url) {
            warnings.append(.init("base64url-padding", "the request uses padded base64url ([WRQ-2])"))
        }
        let dr: Data
        do { dr = try Base64URL.decode(deviceRequestBase64Url) }
        catch { throw CheckinWalletError.malformedDeviceRequest("base64url") }
        let opts = DeviceRequestBuilder.Options(
            docType: SmartHealthCheckinConstants.mdocDocType,
            namespace: SmartHealthCheckinConstants.mdocNamespace,
            element: SmartHealthCheckinConstants.mdocElementIdentifier,
            requestCarrierKey: SmartHealthCheckinConstants.mdocRequestCarrierKey,
            intentToRetain: true
        )
        let parsedReq: CheckinDeviceRequest
        do { parsedReq = try DeviceRequestParser.parse(dr, expecting: opts) }
        catch DeviceRequestParser.Error.missingRequestInfo { throw CheckinWalletError.missingSmartRequestCarrier }
        catch { throw CheckinWalletError.malformedDeviceRequest(String(describing: error)) }
        warnings += parsedReq.warnings
        let docReq = parsedReq.docRequests[0]
        guard let smartJSON = docReq.itemsRequest.smartRequestJSON(
            carrierKey: SmartHealthCheckinConstants.mdocRequestCarrierKey
        ) else {
            throw CheckinWalletError.missingSmartRequestCarrier
        }
        // [WRQ-6] The SMART request, validated per §5.
        let smartReq: SmartHealthCheckinRequest
        do { smartReq = try SmartHealthCheckinRequest.parse(smartJSON) }
        catch {
            throw CheckinWalletError.smartRequestInvalid(ValidationReport(issues: [
                .init(severity: .error, path: "$", message: String(describing: error))
            ]))
        }
        let validationReport = SmartHealthCheckinValidator.validate(request: smartReq)
        if validationReport.hasErrors { throw CheckinWalletError.smartRequestInvalid(validationReport) }

        // [WRQ-7] encryptionInfo needs a usable P-256 key; other problems warn.
        do {
            let ei = try EncryptionInfo.decodeLenient(try Base64URL.decode(encryptionInfoBase64Url))
            warnings += ei.warnings
        } catch {
            throw CheckinWalletError.noUsableEncryptionKey(String(describing: error))
        }

        // Pull the intentToRetain hint for the SMART element specifically.
        var intent = false
        for ns in docReq.itemsRequest.elementsByNamespace where ns.namespace == SmartHealthCheckinConstants.mdocNamespace {
            for e in ns.elements where e.element == SmartHealthCheckinConstants.mdocElementIdentifier {
                intent = e.intentToRetain
            }
        }
        let parsed = ParsedCheckinRequest(
            smartRequest: smartReq,
            smartRequestValidation: validationReport,
            intentToRetain: intent,
            docType: docReq.itemsRequest.docType,
            namespace: SmartHealthCheckinConstants.mdocNamespace,
            element: SmartHealthCheckinConstants.mdocElementIdentifier,
            readerAuth: docReq.readerAuth,
            itemsRequestTag24Bytes: docReq.itemsRequestTag24Bytes,
            warnings: warnings,
            unsupportedItems: SmartHealthCheckinValidator.unsupportedItems(in: smartReq)
        )
        let assembler = WalletResponseAssembler(
            parsed: parsed,
            encryptionInfoBase64Url: encryptionInfoBase64Url,
            origin: CheckinOrigin.serialize(origin)
        )
        return (parsed, assembler)
    }

    /// As above, with the origin as the platform delivers it on iOS: a URL.
    public static func handleRequest(
        deviceRequestBase64Url: String,
        encryptionInfoBase64Url: String,
        origin: URL,
        protocol dcProtocol: String? = nil
    ) throws -> (parsed: ParsedCheckinRequest, assembler: WalletResponseAssembler) {
        try handleRequest(deviceRequestBase64Url: deviceRequestBase64Url,
                          encryptionInfoBase64Url: encryptionInfoBase64Url,
                          origin: CheckinOrigin.serialize(origin), protocol: dcProtocol)
    }

    /// Validate `readerAuth` if present, against a list of trusted reader
    /// public keys. A value of `nil` means "no readerAuth was supplied" — the
    /// wallet decides whether to proceed based on its policy. Returns `true`
    /// only on a positive verification.
    public static func verifyReaderAuth(
        _ parsed: ParsedCheckinRequest,
        sessionTranscript: Data,
        trustedReaderKeys: [P256.Signing.PublicKey]
    ) -> Bool {
        guard let readerAuth = parsed.readerAuth else { return false }
        let payload = ReaderAuth.readerAuthenticationBytes(
            sessionTranscript: sessionTranscript,
            itemsRequestTag24Bytes: parsed.itemsRequestTag24Bytes
        )
        for k in trustedReaderKeys {
            do {
                try COSESign1Signer.verify(readerAuth, publicKey: k, detachedPayload: payload)
                return true
            } catch { continue }
        }
        return false
    }
}
