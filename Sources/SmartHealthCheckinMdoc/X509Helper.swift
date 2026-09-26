// SPDX-License-Identifier: MIT
//
// X.509 helpers:
//  * pull the P-256 public key out of an `x5chain` leaf certificate, and
//  * mint the self-signed certificate a Wallet puts in `issuerAuth`'s x5chain
//    ([WRS-4]) and a Verifier puts in `readerAuth`'s ([RA-1]) when the caller
//    has no certificate of its own. Certificates at this layer may be
//    self-signed (§7); strict mdoc software needs one to find the key.

import Foundation
import Crypto
import SwiftASN1
import X509

public enum X509Helper {
    public static func p256PublicKey(fromCertificate der: Data) -> P256.Signing.PublicKey? {
        guard let cert = try? Certificate(derEncoded: Array(der)) else { return nil }
        return P256.Signing.PublicKey(cert.publicKey)
    }

    /// A DER-encoded self-signed ES256 certificate for `key`, valid from a
    /// minute before `notBefore` until `notAfter`.
    public static func selfSignedCertificate(
        for key: P256.Signing.PrivateKey,
        commonName: String,
        notBefore: Date = Date(),
        notAfter: Date = Date().addingTimeInterval(24 * 60 * 60)
    ) throws -> Data {
        let name = try DistinguishedName { CommonName(commonName) }
        var serial = [UInt8](repeating: 0, count: 16)
        for i in serial.indices { serial[i] = UInt8.random(in: 0...255) }
        serial[0] &= 0x7f  // positive
        let cert = try Certificate(
            version: .v3,
            serialNumber: .init(bytes: serial[...]),
            publicKey: .init(key.publicKey),
            notValidBefore: notBefore.addingTimeInterval(-60),
            notValidAfter: notAfter,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
            },
            issuerPrivateKey: .init(key)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return Data(serializer.serializedBytes)
    }
}
