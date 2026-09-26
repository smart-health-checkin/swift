// SPDX-License-Identifier: MIT
//
// Receiver warnings (§2 [RCV-0]..[RCV-2]). A producer builds exactly what §8
// describes; a receiver fails only where §8 marks a step as a failure and
// reports every other problem as a warning and carries on.

import Foundation

public struct CheckinWarning: Equatable, Sendable, CustomStringConvertible {
    /// A short, stable code, e.g. `device-signature` or `mso-validity-info`.
    /// The codes match the spec's conformance cases.
    public var code: String
    public var message: String

    public init(_ code: String, _ message: String) {
        self.code = code; self.message = message
    }

    public var description: String { "\(code): \(message)" }
}

/// Origin serialization for the SessionTranscript ([TR-2]).
public enum CheckinOrigin {
    /// The ASCII serialization of a web origin: `scheme://host[:port]`, with the
    /// port only when it isn't the scheme's default, and no trailing slash. A
    /// platform may deliver the origin as a URL (iOS gives `https://host/`);
    /// this normalizes it. Anything that isn't an http(s) URL, such as
    /// `android:apk-key-hash:…`, is returned unchanged.
    public static func serialize(_ origin: String) -> String {
        guard let c = URLComponents(string: origin),
              let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = c.host, !host.isEmpty else { return origin }
        var out = "\(scheme)://\(host.lowercased())"
        if let port = c.port, !((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) {
            out += ":\(port)"
        }
        return out
    }

    public static func serialize(_ origin: URL) -> String { serialize(origin.absoluteString) }
}
