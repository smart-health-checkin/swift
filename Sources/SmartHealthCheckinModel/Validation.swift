// SPDX-License-Identifier: MIT
//
// §5 request structural validation and §6.4 verifier cross-validation.
//
// Structural validation here goes beyond what `parse` checks (which is mostly
// shape and required-member presence). These are issues a wallet/responder
// or verifier would otherwise have to spot themselves.

import Foundation

public struct ValidationIssue: Equatable, Sendable, CustomStringConvertible {
    public enum Severity: String, Sendable, Equatable {
        case error
        case warning
    }
    public var severity: Severity
    public var path: String
    public var message: String

    public init(severity: Severity, path: String, message: String) {
        self.severity = severity; self.path = path; self.message = message
    }

    public var description: String { "\(severity.rawValue.uppercased()) \(path): \(message)" }
}

public struct ValidationReport: Equatable, Sendable, CustomStringConvertible {
    public var issues: [ValidationIssue]
    public init(issues: [ValidationIssue] = []) { self.issues = issues }

    public var hasErrors: Bool { issues.contains { $0.severity == .error } }
    public var errors: [ValidationIssue] { issues.filter { $0.severity == .error } }
    public var warnings: [ValidationIssue] { issues.filter { $0.severity == .warning } }

    public mutating func error(_ path: String, _ message: String) {
        issues.append(.init(severity: .error, path: path, message: message))
    }
    public mutating func warning(_ path: String, _ message: String) {
        issues.append(.init(severity: .warning, path: path, message: message))
    }

    public var description: String { issues.map(\.description).joined(separator: "\n") }
}

/// The result of checking a SMART response against the request it answers
/// (§6.4). Only [XV-1]/[XV-2] problems are errors in `report` (reject the
/// whole response). Everything else affects one Artifact or one item, and is
/// reported as a warning plus the per-Artifact and per-item results below.
public struct CrossCheck: Equatable, Sendable {
    public enum ItemOutcome: Equatable, Sendable {
        /// The item has exactly one valid status row.
        case status(RequestItemStatus.Code)
        /// No valid status: the row is missing, duplicated, or unparseable ([XV-3]).
        case unknown(reason: String)
    }
    public struct DisregardedArtifact: Equatable, Sendable {
        public var id: String?
        public var reason: String
    }
    public var report: ValidationReport
    /// Artifacts that passed every check, in response order ([XV-4]).
    public var usableArtifacts: [Artifact]
    /// Artifacts the Verifier must not use, with why ([XV-4]..[XV-10]).
    public var disregardedArtifacts: [DisregardedArtifact]
    /// One outcome per request item, keyed by item id.
    public var itemOutcomes: [String: ItemOutcome]

    /// Artifacts usable for one item.
    public func usableArtifacts(for itemId: String) -> [Artifact] {
        usableArtifacts.filter { $0.fulfills.contains(itemId) }
    }
}

public enum SmartHealthCheckinValidator {

    /// §5 request validation. Errors mean the request as a whole must be
    /// rejected ([REQ-2], [ITEM-2]). An item whose selector the Wallet can't
    /// process is not an error: it is reported as a warning and the Wallet
    /// answers it `unsupported` ([SEL-8], [SEL-9], [SEL-10], [FORM-1]); see
    /// `unsupportedItems(in:)`.
    public static func validate(request: SmartHealthCheckinRequest) -> ValidationReport {
        var r = ValidationReport()
        if request.type != SmartHealthCheckinConstants.requestType {
            r.error("$.type", "must be exactly '\(SmartHealthCheckinConstants.requestType)'")
        }
        if request.version != SmartHealthCheckinConstants.modelVersion {
            r.error("$.version", "must be exactly '\(SmartHealthCheckinConstants.modelVersion)'")
        }
        if request.id.isEmpty { r.error("$.id", "must be non-empty") }

        var ids = Set<String>()
        for (i, item) in request.items.enumerated() {
            let p = "$.items[\(i)]"
            if item.id.isEmpty { r.error("\(p).id", "must be non-empty") }
            if !ids.insert(item.id).inserted {
                r.error("\(p).id", "duplicate item id '\(item.id)'")
            }
            if item.title.isEmpty { r.error("\(p).title", "must be non-empty") }
            if item.accept.isEmpty { r.error("\(p).accept", "must be non-empty array") }
            if let reason = item.unsupportedReason {
                r.warning("\(p).content", "item '\(item.id)' is unsupported: \(reason)")
            }
        }
        return r
    }

    /// Items a Wallet must answer `unsupported`, keyed by item id, with why.
    public static func unsupportedItems(in request: SmartHealthCheckinRequest) -> [String: String] {
        var out: [String: String] = [:]
        for item in request.items { if let reason = item.unsupportedReason { out[item.id] = reason } }
        return out
    }

    /// §6.4 Verifier cross-validation, as a report. Errors are only the
    /// whole-response failures ([XV-1], [XV-2]); per-Artifact and per-item
    /// problems are warnings. Use `crossCheck` for the per-Artifact and
    /// per-item results.
    public static func crossValidate(
        request: SmartHealthCheckinRequest,
        response: SmartHealthCheckinResponse
    ) -> ValidationReport {
        crossCheck(request: request, response: response).report
    }

    /// §6.4 Verifier cross-validation. Run after parsing both messages.
    public static func crossCheck(
        request: SmartHealthCheckinRequest,
        response: SmartHealthCheckinResponse
    ) -> CrossCheck {
        var r = ValidationReport()

        // [XV-1] (parse already enforces these for parsed responses) and [XV-2].
        if response.type != SmartHealthCheckinConstants.responseType {
            r.error("$.type", "must be exactly '\(SmartHealthCheckinConstants.responseType)'")
        }
        if response.version != SmartHealthCheckinConstants.modelVersion {
            r.error("$.version", "must be exactly '\(SmartHealthCheckinConstants.modelVersion)'")
        }
        if response.requestId != request.id {
            r.error("$.requestId", "must equal request id (got '\(response.requestId)', expected '\(request.id)')")
        }

        let itemsById = Dictionary(request.items.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var disregarded: [CrossCheck.DisregardedArtifact] = response.disregardedArtifacts.map {
            r.warning("$.artifacts[\($0.index)]", "disregarded: \($0.reason)")
            return .init(id: $0.id, reason: $0.reason)
        }
        var usable: [Artifact] = []
        let requestedReleases = request.fhirVersions ?? []

        for art in response.artifacts {
            func reason() -> String? {
                if art.fulfills.isEmpty { return "fulfills[] is empty" }
                for fid in art.fulfills {
                    guard let item = itemsById[fid] else { return "fulfills names '\(fid)', which is not a request item" }
                    if !item.accept.contains(art.mediaType) {
                        return "mediaType '\(art.mediaType)' is not in accept[] for item '\(fid)'"
                    }
                }
                switch art {
                case .ext:
                    return "mediaType '\(art.mediaType)' is not a supported media type"
                case .smartHealthCard(let a):
                    if a.verifiableCredentials.isEmpty { return "verifiableCredential[] is empty" }
                case .fhirJson(let a):
                    if a.fhirVersion.isEmpty { return "fhirVersion is empty" }
                    if a.value["resourceType"]?.stringValue == nil { return "value has no resourceType" }
                    // [XV-8] SHOULD: a release the request didn't list is unusable.
                    if !requestedReleases.isEmpty && !requestedReleases.contains(a.fhirVersion) {
                        return "fhirVersion '\(a.fhirVersion)' is not among the request's fhirVersions"
                    }
                    // [XV-10] A QuestionnaireResponse answering a form item with a canonical echoes it exactly.
                    if a.value["resourceType"]?.stringValue == "QuestionnaireResponse" {
                        for fid in art.fulfills {
                            if case .formFhir(let f)? = itemsById[fid]?.content, let qc = f.questionnaireCanonical,
                               a.value["questionnaire"]?.stringValue != qc {
                                return "QuestionnaireResponse.questionnaire does not equal '\(qc)' for item '\(fid)'"
                            }
                        }
                    }
                }
                return nil
            }
            if let why = reason() {
                r.warning("$.artifacts[id=\(art.id)]", "disregarded: \(why)")
                disregarded.append(.init(id: art.id, reason: why))
            } else {
                usable.append(art)
            }
        }

        // [XV-3] One valid status row per item; rows for other ids are ignored.
        var rowsByItem: [String: [RequestItemStatus]] = [:]
        for st in response.requestStatus {
            if itemsById[st.item] == nil {
                r.warning("$.requestStatus", "ignored a status row for '\(st.item)', which is not a request item")
                continue
            }
            rowsByItem[st.item, default: []].append(st)
        }
        let badRowItems = Set(response.disregardedStatus.compactMap(\.id))
        var outcomes: [String: CrossCheck.ItemOutcome] = [:]
        for item in request.items {
            let rows = rowsByItem[item.id] ?? []
            if badRowItems.contains(item.id) {
                outcomes[item.id] = .unknown(reason: "its status row could not be read")
            } else if rows.count == 1 {
                outcomes[item.id] = .status(rows[0].status)
            } else if rows.isEmpty {
                outcomes[item.id] = .unknown(reason: "no status row")
            } else {
                outcomes[item.id] = .unknown(reason: "\(rows.count) status rows")
            }
            if case .unknown(let why)? = outcomes[item.id] {
                r.warning("$.requestStatus", "item '\(item.id)' has no valid status: \(why)")
            }
        }

        // [XV-12] SHOULD flag fulfilled/partial items no usable Artifact lists.
        for (id, outcome) in outcomes {
            if case .status(let code) = outcome, code == .fulfilled || code == .partial,
               !usable.contains(where: { $0.fulfills.contains(id) }) {
                r.warning("$.requestStatus", "item '\(id)' is \(code.rawValue) but no usable Artifact lists it")
            }
        }
        return CrossCheck(report: r, usableArtifacts: usable, disregardedArtifacts: disregarded, itemOutcomes: outcomes)
    }
}
