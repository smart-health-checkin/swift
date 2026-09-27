# SmartHealthCheckin

A Swift Package implementing **[SMART Health Check‑in 1.0](https://smart-health-checkin.org/spec/)**, a same‑device W3C Digital Credentials API protocol for clinical check‑in, layered on top of `org-iso-mdoc` (CBOR + COSE_Sign1 + HPKE).

The package exposes both **Verifier** (clinic / kiosk) and **Wallet** (patient app) roles, plus the underlying primitives (clinical model, deterministic CBOR, COSE_Sign1, HPKE binding, x509) so applications can compose their own flows.

It implements the whole spec and passes every spec conformance case ([Testing](#testing)). There is no reference iOS wallet app built on it yet.

## Requirements

- Swift 5.9+
- iOS 17 / macOS 14 / Mac Catalyst 17 / tvOS 17 / watchOS 10 / visionOS 1
  - These minimums are required for [HPKE](https://datatracker.ietf.org/doc/html/rfc9180) in CryptoKit.
- On Apple platforms, [`swift-crypto`](https://github.com/apple/swift-crypto) re-exports CryptoKit so there is no runtime cost; on Linux the same APIs are used so `swift test` works portably.

## Install

```swift
.package(url: "https://github.com/smart-health-checkin/swift.git", from: "0.2.0")
```

Releases are `vX.Y.Z` tags; `from:` takes any later compatible one.

Then, depending on what you need:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "SmartHealthCheckin", package: "swift"),
    ]
)
```

Targets exposed (use the most specific one you need):

| Library                                         | What you get                                                       |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| `SmartHealthCheckin`                            | High-level `CheckinVerifier` / `CheckinWallet` facades             |
| `SmartHealthCheckinModel`                       | [§5](https://smart-health-checkin.org/spec/#5-clinical-request-model)/[§6](https://smart-health-checkin.org/spec/#6-clinical-response-model) clinical JSON model + strict parser + [§6.4](https://smart-health-checkin.org/spec/#6-4-verifier-cross-validation) cross‑validation  |
| `SmartHealthCheckinCBOR`                        | Deterministic CBOR codec, Tag(24) helpers, byte-range slice extraction |
| `SmartHealthCheckinMdoc`                        | COSE_Key, COSE_Sign1, SessionTranscript, DeviceRequest/Response, HPKE wrappers, x509 cert helpers |

## Verifier (clinic / kiosk)

```swift
import SmartHealthCheckin
import SmartHealthCheckinModel

let request = SmartHealthCheckinRequest(
    id: "checkin-2025-01",
    items: [
        .init(
            id: "imm",
            title: "Immunization history",
            content: .selectionFhir(.init(
                profiles: ["http://hl7.org/fhir/StructureDefinition/Immunization"]
            )),
            accept: [SmartHealthCheckinConstants.mediaTypeSmartHealthCard]
        )
    ]
)

// 1. Build the request to send through the W3C DC API.
let made = try CheckinVerifier.makeRequest(smartRequest: request)
// made.deviceRequestBase64Url, made.encryptionInfoBase64Url
// → pass these into navigator.credentials.get({ digital: { requests: [...] } }) on the page

// 2. After the DC API returns, open the response. `origin` MUST be the
//    page's authenticated origin (the same one the browser bound the call to).
//    It throws only when the response can't be used at all: it doesn't
//    decrypt, has no SMART document or response element, or answers a
//    different request (§8.5, [XV-1], [XV-2]).
let result = try CheckinVerifier.openResponse(
    retainedState: made.retainedState,
    origin: "https://clinic.example",
    dcapiResponseBase64Url: dcapiResponse,
    protocol: credential.protocol          // optional; a wrong value is a warning
)

// 3. Use what passed §6.4; log what didn't.
for warning in result.warnings { log("\(warning.code): \(warning.message)") }
for item in request.items {
    switch result.crossCheck.itemOutcomes[item.id] {
    case .status(let code)?: use(code, result.crossCheck.usableArtifacts(for: item.id))
    case .unknown(let why)?, nil: log("no valid status for \(item.id): \(String(describing: why))")
    }
}
```

The Verifier is strict about what it builds and permissive about what it
receives ([§2](https://smart-health-checkin.org/spec/#2-terminology-and-conventions) [RCV-0](https://smart-health-checkin.org/spec/#RCV-0)..[RCV-2](https://smart-health-checkin.org/spec/#RCV-2)). Signature, digest, MSO, validity, version, and
padding problems don't throw: they come back in `result.warnings` with a short
code (`issuer-signature`, `device-signature`, `digest`, `mso-validity`, …), and
the individual booleans (`issuerSignatureValid`, `deviceSignatureValid`,
`valueDigestMatches`) stay available. [§6.4](https://smart-health-checkin.org/spec/#6-4-verifier-cross-validation) problems affect one Artifact or one
item: `result.crossCheck` lists the usable Artifacts, the disregarded ones with
reasons, and each item's outcome. `result.allChecksPass` is `true` only when
there are no warnings of either kind.

### Reader-authenticated requests

The kiosk can sign the request with a known reader key:

```swift
let made = try CheckinVerifier.makeRequest(
    smartRequest: request,
    readerSigningKey: readerKey,                 // P256.Signing.PrivateKey
    readerCertificateChain: [readerLeafCertDER], // optional; a self-signed one is minted otherwise
    origin: "https://clinic.example"
)
```

## Wallet (patient app)

```swift
import SmartHealthCheckin

let parsed = try CheckinWallet.handleRequest(
    deviceRequestBase64Url: deviceRequestB64u,
    encryptionInfoBase64Url: encryptionInfoB64u,
    origin: requestingWebsiteOrigin    // from the platform only; a URL (iOS) works too
)

// Surface parsed.parsed.smartRequest to the user for item-by-item choice.
// Items in parsed.parsed.unsupportedItems (unknown or malformed selectors)
// get status `unsupported`; parsed.parsed.warnings lists request problems
// that didn't stop the Wallet (§8.4).

// Optional: verify readerAuth against your trust list.
let st = SessionTranscript.dcapi(
    encryptionInfoBase64Url: encryptionInfoB64u, origin: "https://clinic.example"
)
let readerOK = CheckinWallet.verifyReaderAuth(
    parsed.parsed,
    sessionTranscript: st,
    trustedReaderKeys: walletTrustedReaders
)

// Build the response with the user's selected artifacts.
let smartResponse = SmartHealthCheckinResponse(
    requestId: parsed.parsed.smartRequest.id,
    artifacts: [
        .smartHealthCard(.init(id: "shc1", fulfills: ["imm"], verifiableCredentials: [shcJWS]))
    ],
    requestStatus: [.init(item: "imm", status: .fulfilled)]
)
let dcapiResponseB64u = try parsed.assembler.reply(
    smartResponse: smartResponse,
    issuerKey: credentialIssuerKey,        // P256.Signing.PrivateKey
    deviceKey: credentialDeviceKey         // P256.Signing.PrivateKey
    // issuerCertificateChain: optional; by default a self-signed certificate
    // for issuerKey goes in x5chain ([WRS-4])
)
// → return this as the dcapi response
```

`reply` refuses to build a response a strict Verifier would reject or partly
disregard (a missing or doubled status row, an Artifact whose media type the
item doesn't accept, and so on). A Holder who declines everything is answered
with every item `declined` ([HOLD-4](https://smart-health-checkin.org/spec/#HOLD-4)).

On iOS, the Identity Document Provider extension sees `requestInfo` only once
the patient interacts: call `handleRequest` inside `sendResponse`, with
`context.requestingWebsiteOrigin` as the origin.

## Lower layers

If you need to compose your own flow, every primitive is reachable:

```swift
import SmartHealthCheckinCBOR
import SmartHealthCheckinMdoc

let st = SessionTranscript.dcapi(
    encryptionInfoBase64Url: encInfoB64u, origin: origin
)
let sealed = try CheckinHPKE.seal(
    plaintext: deviceResponseBytes,
    recipientPublicKey: recipientKey,
    info: st
)
```

The CBOR codec provides byte-range slice extraction so you can hash exactly what was on the wire (mdoc `IssuerSignedItem` digests are taken over the **received** `Tag(24, bstr)` wrapper bytes, never a re-encoded form):

```swift
let decoded = try CBORDecoder.lenient.decodeWithSlices(deviceResponseBytes)
let itemSlice = try decoded.slice(at: [
    .key(.textString("documents")),
    .index(0),
    .key(.textString("issuerSigned")),
    .key(.textString("nameSpaces")),
    .key(.textString("org.smarthealthit.checkin")),
    .index(0),
])
let digest = SHA256.hash(data: itemSlice.source)
```

## Spec compliance notes

The library bakes in the [spec](https://smart-health-checkin.org/spec/)'s load‑bearing details:

- Identifiers are fixed: docType `org.smarthealthit.checkin.1`, namespace `org.smarthealthit.checkin`, element `smart_health_checkin_response`, request carrier key `org.smarthealthit.checkin.request`.
- The SMART JSON request body sits in `requestInfo[carrierKey]` as a CBOR **text string** (not a map, not base64url) per [§8.2](https://smart-health-checkin.org/spec/#8-2-verifier-request-construction).
- [§5.1](https://smart-health-checkin.org/spec/#5-1-encoding-rules) strictness: the JSON parser rejects duplicate object members. Foundation's `JSONDecoder` and `JSONSerialization` silently accept them; the library does not use them.
- COSE_Sign1 ES256 signatures are raw `R || S` (64 bytes), not DER.
- `issuerAuth` payload is `Tag(24, bstr .cbor MSO)` (attached), with the issuer certificate in `x5chain` (label 33, unprotected). `deviceSignature` and `readerAuth` payloads are **detached** (`nil`): the receiver rebuilds `DeviceAuthenticationBytes` / `ReaderAuthenticationBytes` from its own `SessionTranscript`. A received attached device payload that differs from the rebuilt bytes doesn't verify.
- The MSO carries `validityInfo` (`signed` = `validFrom` = signing time, whole seconds, UTC).
- Map ordering is RFC 8949 deterministic; non-shortest int / length encodings are rejected.
- HPKE: DHKEM(P‑256, HKDF‑SHA256) + HKDF‑SHA256 + AES‑128‑GCM, `info = SessionTranscript`, `aad = h''`, base mode.
- `DeviceAuthentication` binds the **exact** received `deviceSigned.nameSpaces` tag‑24 bytes — the library does not hardcode `{}`.
- The SessionTranscript origin is the ASCII serialization of the web origin, no trailing slash ([TR-2](https://smart-health-checkin.org/spec/#TR-2)); `CheckinOrigin.serialize` normalizes a platform-supplied URL.
- Receivers fail only where [§8](https://smart-health-checkin.org/spec/#8-same-device-presentation-flow) says so and warn otherwise ([RCV-0](https://smart-health-checkin.org/spec/#RCV-0)..[RCV-2](https://smart-health-checkin.org/spec/#RCV-2)). A malformed selector makes only its item `unsupported`; a malformed Artifact or status row affects only itself ([XV-3](https://smart-health-checkin.org/spec/#XV-3), [XV-4](https://smart-health-checkin.org/spec/#XV-4)).
- [§6.4](https://smart-health-checkin.org/spec/#6-4-verifier-cross-validation) cross‑validation (`SmartHealthCheckinValidator.crossCheck`): an Artifact is usable only if every item it lists exists and accepts its `mediaType`, its FHIR release is one the request listed, and a `QuestionnaireResponse` echoes the requested canonical exactly.

## Testing

```sh
scripts/fetch-spec.sh   # the spec's fixtures and conformance cases, into the gitignored fixtures/ and spec-conformance/
swift test
```

`SpecConformanceTests` runs every spec conformance case (request and response
JSON, cross-validation, request CBOR, transcript, HPKE, mdoc verification) and
must pass them all: `conformance/known-failures.json` lists none. For warning
cases it also checks the expected warning code is reported. CI then checks the
credentials this wallet builds with the spec's [reference verifier](https://github.com/smart-health-checkin/spec/tree/main/conformance/reference).

Both read the spec at a pinned tag (`SPEC_REF` in `scripts/fetch-spec.sh`,
currently `v1.0.0-draft.1`). Set `SPEC_DIR=../spec` to test against a local
spec checkout.

Unit tests cover the model layer, CBOR determinism and slice extraction, a COSE_Sign1 round trip, HPKE seal and open, DeviceRequest and DeviceResponse building and parsing with positive and negative cases, and a Verifier-to-Wallet round trip. A fixture test (`SampleFixtureTests`) decodes a captured `DigitalCredentialsRequest` ([`sample.json`](Tests/SmartHealthCheckinTests/Fixtures/sample.json)) and verifies its `readerAuth` against the embedded leaf certificate.

## Threat model and responsibilities

The library implements the protocol; production deployments still need to:

- Decide what, if anything, to trust beyond integrity. Signatures show the mdoc is intact and well formed, not who issued it ([§7](https://smart-health-checkin.org/spec/#7-trust-framework)); supply `trustedIssuerKeys` only if a deployment profile defines trusted issuers.
- Bind to the authenticated origin from the platform credential manager / browser. Never accept an origin from inside the SMART JSON body.
- Treat the verifier's `VerifierRetainedState` as ephemeral session state. Rotate per request.
- Look at `result.warnings`: an MSO outside its validity window is reported as `mso-validity` ([VRS-10](https://smart-health-checkin.org/spec/#VRS-10)), not rejected.
- Handle `intentToRetain = false` semantics in your data layer.

## License

MIT.
