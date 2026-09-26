// SPDX-License-Identifier: MIT
import XCTest
@testable import SmartHealthCheckinModel

final class JSONStrictTests: XCTestCase {
    func testRoundTripsObject() throws {
        let src = #"{"a":1,"b":"x","c":[true,false,null,3.5],"d":{"e":2}}"#
        let v = try JSONStrictParser.parse(src)
        let out = JSONStrictWriter.encodeString(v)
        // Member order is preserved.
        XCTAssertTrue(out.contains("\"a\":1"))
        XCTAssertTrue(out.contains("\"d\":{\"e\":2}"))
        // Round-trip stable.
        let v2 = try JSONStrictParser.parse(out)
        XCTAssertEqual(v, v2)
    }

    func testRejectsDuplicateMembers() throws {
        XCTAssertThrowsError(try JSONStrictParser.parse(#"{"a":1,"a":2}"#)) { e in
            guard let je = e as? JSONStrictError, case .duplicateMember(let name, _) = je else {
                return XCTFail("expected duplicateMember, got \(e)")
            }
            XCTAssertEqual(name, "a")
        }
    }

    func testRejectsTrailingData() {
        XCTAssertThrowsError(try JSONStrictParser.parse(#"{"a":1}{}"#))
    }

    func testRejectsTopLevelNonObjectWhenRequired() {
        XCTAssertThrowsError(try JSONStrictParser.parseObject(Data("[]".utf8)))
    }

    func testHandlesUnicodeAndSurrogates() throws {
        // 𝄞 — musical G clef, U+1D11E, surrogate pair \uD834\uDD1E
        let v = try JSONStrictParser.parse(#""\uD834\uDD1E""#)
        XCTAssertEqual(v, .string("\u{1D11E}"))
    }

    func testRejectsInvalidEscape() {
        XCTAssertThrowsError(try JSONStrictParser.parse(#""\q""#))
    }
}

final class RequestModelTests: XCTestCase {
    func testParsesAndRoundTripsCanonicalRequest() throws {
        let json = #"""
        {
          "type": "smart-health-checkin-request",
          "version": "1",
          "id": "demo-1",
          "purpose": "Clinic check-in",
          "fhirVersions": ["4.0.1"],
          "items": [
            {
              "id": "patient",
              "title": "Patient demographics",
              "required": true,
              "content": {
                "kind": "selection.fhir",
                "profiles": ["http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient"]
              },
              "accept": ["application/fhir+json"]
            },
            {
              "id": "intake",
              "title": "Intake",
              "content": {
                "kind": "form.fhir",
                "questionnaire": {
                  "resourceType": "Questionnaire",
                  "title": "Intake"
                }
              },
              "accept": ["application/fhir+json"]
            }
          ]
        }
        """#
        let req = try SmartHealthCheckinRequest.parse(json)
        XCTAssertEqual(req.id, "demo-1")
        XCTAssertEqual(req.items.count, 2)
        XCTAssertEqual(req.items[0].id, "patient")
        if case .selectionFhir(let s) = req.items[0].content {
            XCTAssertEqual(s.profiles?.first, "http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient")
        } else { XCTFail("expected selection.fhir") }
        if case .formFhir(let f) = req.items[1].content {
            XCTAssertNotNil(f.questionnaire)
        } else { XCTFail("expected form.fhir") }

        let out = req.toJSONString()
        let req2 = try SmartHealthCheckinRequest.parse(out)
        XCTAssertEqual(req, req2)
    }

    // [SEL-8] A selector problem makes only that item unsupported; the request stands.
    func testConflictingSelectorMembersMakeItemUnsupported() throws {
        let json = #"{"type":"smart-health-checkin-request","version":"1","id":"x","items":[{"id":"a","title":"A","content":{"kind":"selection.fhir","questionnaire":{}},"accept":["application/fhir+json"]},{"id":"b","title":"B","content":{"kind":"selection.fhir"},"accept":["application/fhir+json"]}]}"#
        let req = try SmartHealthCheckinRequest.parse(json)
        XCTAssertFalse(SmartHealthCheckinValidator.validate(request: req).hasErrors)
        XCTAssertNotNil(req.items[0].unsupportedReason)
        XCTAssertNil(req.items[1].unsupportedReason)
        XCTAssertEqual(Set(SmartHealthCheckinValidator.unsupportedItems(in: req).keys), ["a"])
        // The malformed selector round-trips verbatim.
        XCTAssertEqual(try SmartHealthCheckinRequest.parse(req.toJSONString()), req)
    }

    // [REQ-2] content that isn't an object with a string kind invalidates the whole request.
    func testNonObjectContentRejectsRequest() {
        let json = #"{"type":"smart-health-checkin-request","version":"1","id":"x","items":[{"id":"a","title":"A","content":"x","accept":["application/fhir+json"]}]}"#
        XCTAssertThrowsError(try SmartHealthCheckinRequest.parse(json))
    }

    func testValidationFlagsDuplicateItemIds() throws {
        let req = SmartHealthCheckinRequest(
            id: "r1",
            items: [
                .init(id: "a", title: "A", content: .selectionFhir(.init()), accept: ["application/fhir+json"]),
                .init(id: "a", title: "B", content: .selectionFhir(.init()), accept: ["application/fhir+json"])
            ]
        )
        let report = SmartHealthCheckinValidator.validate(request: req)
        XCTAssertTrue(report.hasErrors)
        XCTAssertTrue(report.errors.contains { $0.message.contains("duplicate item id") })
    }
}

final class ResponseModelTests: XCTestCase {
    func testParsesFhirAndShcArtifacts() throws {
        let json = #"""
        {
          "type":"smart-health-checkin-response",
          "version":"1",
          "requestId":"r-1",
          "artifacts":[
            {
              "id":"a1",
              "mediaType":"application/fhir+json",
              "fhirVersion":"4.0.1",
              "fulfills":["x"],
              "value":{"resourceType":"Patient"}
            },
            {
              "id":"a2",
              "mediaType":"application/smart-health-card",
              "fulfills":["y"],
              "value":{"verifiableCredential":["shc:/567"]}
            }
          ],
          "requestStatus":[
            {"item":"x","status":"fulfilled"},
            {"item":"y","status":"partial","message":"only labs"}
          ]
        }
        """#
        let resp = try SmartHealthCheckinResponse.parse(json)
        XCTAssertEqual(resp.artifacts.count, 2)
        XCTAssertEqual(resp.artifacts[0].mediaType, "application/fhir+json")
        XCTAssertEqual(resp.artifacts[1].fulfills, ["y"])
        XCTAssertEqual(resp.requestStatus[1].status, .partial)

        let s = resp.toJSONString()
        XCTAssertEqual(try SmartHealthCheckinResponse.parse(s), resp)
    }

    // [XV-4], [XV-9] A health card with an outer fhirVersion is disregarded; the response stands.
    func testShcArtifactWithOuterFhirVersionIsDisregarded() throws {
        let json = #"""
        {"type":"smart-health-checkin-response","version":"1","requestId":"r-1","artifacts":[
          {"id":"a","mediaType":"application/smart-health-card","fhirVersion":"4.0.1","fulfills":["x"],"value":{"verifiableCredential":["shc:/1"]}},
          {"id":"b","mediaType":"application/fhir+json","fhirVersion":"4.0.1","fulfills":["x"],"value":{"resourceType":"Patient"}}
        ],"requestStatus":[{"item":"x","status":"fulfilled"},{"item":"x","status":"bogus"}]}
        """#
        let resp = try SmartHealthCheckinResponse.parse(json)
        XCTAssertEqual(resp.artifacts.map(\.id), ["b"])
        XCTAssertEqual(resp.disregardedArtifacts.map(\.id), ["a"])
        XCTAssertEqual(resp.disregardedStatus.count, 1)
        // Set-aside entries go back in place, so the response round-trips.
        XCTAssertEqual(try SmartHealthCheckinResponse.parse(resp.toJSONString()), resp)
    }

    // [XV-1] type and version are whole-response checks.
    func testWrongVersionRejectsResponse() {
        let json = #"{"type":"smart-health-checkin-response","version":"2","requestId":"r","artifacts":[],"requestStatus":[]}"#
        XCTAssertThrowsError(try SmartHealthCheckinResponse.parse(json))
    }
}

final class CrossValidationTests: XCTestCase {
    func makeRequest() -> SmartHealthCheckinRequest {
        SmartHealthCheckinRequest(
            id: "demo-1",
            items: [
                .init(id: "patient", title: "Patient demographics",
                      content: .selectionFhir(.init(profilesFrom: ["http://hl7.org/fhir/us/core"])),
                      accept: ["application/fhir+json"]),
                .init(id: "intake", title: "Intake",
                      content: .formFhir(.init(questionnaireCanonical: "https://example.org/Q/intake|1")),
                      accept: ["application/fhir+json"]),
                .init(id: "summary", title: "Summary",
                      content: .selectionFhir(.init(profilesFrom: ["http://hl7.org/fhir/us/core"])),
                      accept: ["application/fhir+json", "application/smart-health-card"])
            ]
        )
    }

    func testHappyPath() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "demo-1",
            artifacts: [
                .fhirJson(.init(id: "art-1", fulfills: ["patient"], fhirVersion: "4.0.1",
                                value: .object([("resourceType", .string("Patient"))]))),
                .smartHealthCard(.init(id: "art-2", fulfills: ["summary"], verifiableCredentials: ["shc:/567"]))
            ],
            requestStatus: [
                .init(item: "patient", status: .fulfilled),
                .init(item: "intake", status: .declined),
                .init(item: "summary", status: .fulfilled)
            ]
        )
        let r = SmartHealthCheckinValidator.crossValidate(request: req, response: resp)
        XCTAssertFalse(r.hasErrors, "got: \(r)")
    }

    func testRejectsRequestIdMismatch() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "WRONG", artifacts: [],
            requestStatus: req.items.map { .init(item: $0.id, status: .declined) }
        )
        let r = SmartHealthCheckinValidator.crossValidate(request: req, response: resp)
        XCTAssertTrue(r.errors.contains { $0.path == "$.requestId" })
    }

    func testRejectsArtifactMediaTypeNotInAccept() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "demo-1",
            artifacts: [
                // patient does not accept smart-health-card
                .smartHealthCard(.init(id: "a", fulfills: ["patient"], verifiableCredentials: ["shc:/x"]))
            ],
            requestStatus: req.items.map { .init(item: $0.id, status: .declined) }
        )
        let c = SmartHealthCheckinValidator.crossCheck(request: req, response: resp)
        XCTAssertFalse(c.report.hasErrors, "only that Artifact is affected ([XV-4], [XV-7])")
        XCTAssertEqual(c.disregardedArtifacts.map(\.id), ["a"])
        XCTAssertTrue(c.disregardedArtifacts[0].reason.contains("not in accept[]"))
        XCTAssertTrue(c.usableArtifacts.isEmpty)
    }

    func testRejectsMissingStatusEntry() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "demo-1", artifacts: [],
            requestStatus: [ .init(item: "patient", status: .declined) ] // missing intake + summary
        )
        let c = SmartHealthCheckinValidator.crossCheck(request: req, response: resp)
        XCTAssertFalse(c.report.hasErrors, "[XV-3] a missing row affects only that item")
        XCTAssertEqual(c.itemOutcomes["patient"], .status(.declined))
        XCTAssertEqual(c.itemOutcomes["intake"], .unknown(reason: "no status row"))
        XCTAssertEqual(c.itemOutcomes["summary"], .unknown(reason: "no status row"))
    }

    func testRejectsDuplicateStatusEntry() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "demo-1", artifacts: [],
            requestStatus: [
                .init(item: "patient", status: .declined),
                .init(item: "patient", status: .fulfilled),
                .init(item: "intake", status: .declined),
                .init(item: "summary", status: .declined)
            ]
        )
        let c = SmartHealthCheckinValidator.crossCheck(request: req, response: resp)
        XCTAssertFalse(c.report.hasErrors, "[XV-3] a doubled row affects only that item")
        XCTAssertEqual(c.itemOutcomes["patient"], .unknown(reason: "2 status rows"))
        XCTAssertEqual(c.itemOutcomes["intake"], .status(.declined))
    }

    func testFulfillsMustReferenceRealItem() {
        let req = makeRequest()
        let resp = SmartHealthCheckinResponse(
            requestId: "demo-1",
            artifacts: [.fhirJson(.init(id: "x", fulfills: ["does-not-exist"], fhirVersion: "4.0.1",
                                        value: .object([("resourceType", .string("Patient"))])))],
            requestStatus: req.items.map { .init(item: $0.id, status: .declined) }
        )
        let c = SmartHealthCheckinValidator.crossCheck(request: req, response: resp)
        XCTAssertFalse(c.report.hasErrors)
        XCTAssertEqual(c.disregardedArtifacts.map(\.id), ["x"])
        XCTAssertTrue(c.disregardedArtifacts[0].reason.contains("not a request item"))
    }
}
