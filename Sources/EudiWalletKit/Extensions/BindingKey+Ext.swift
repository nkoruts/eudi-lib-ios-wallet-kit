//
//  BindingKey+Ext.swift
//  EudiWalletKit
//
//  Created by Nikita Koruts on 12.11.2024.
//

import Foundation
import OpenID4VCI
import JOSESwift

public extension BindingKey {
    public func getProof() throws -> String? {
        switch self {
        case .jwk(let algorithm, let jwk, let privateKey, _):
            return try generateProof(algorithm: algorithm, jwk: jwk, privateKey: privateKey)
        default:
            return nil
        }
    }
    
    private func generateProof(
        algorithm: JWSAlgorithm,
        jwk: JWK,
        privateKey: SecKey
    ) throws -> String? {
        
        let header = try JWSHeader(parameters: [
            "typ": "openid4vci-proof+jwt",
            "alg": algorithm.name,
            "jwk": jwk.toDictionary()
        ])
        let payloadDictionary: [String: Any] = [
            JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded())
        ]
        let payload = Payload(try payloadDictionary.toThrowingJSONData())
        
        guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
            throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
        }
        guard let signer = Signer(signatureAlgorithm: signatureAlgorithm, key: privateKey) else {
            throw ValidationError.error(reason: "Unable to create JWS signer")
        }
        
        let jws = try JWS(
            header: header,
            payload: payload,
            signer: signer
        )
        
        return jws.compactSerializedString
    }
}
