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
    func getProof() async throws -> String? {
        switch self {
        case .jwk(let algorithm, let jwk, let privateKey, _):
            return try await generateProof(
                algorithm: algorithm,
                jwk: jwk,
                privateKey: privateKey
            )
        default:
            return nil
        }
    }
    
    private func generateProof(
        algorithm: JWSAlgorithm,
        jwk: JWK,
        privateKey: SigningKeyProxy
    ) async throws -> String? {
        
        let header = try JWSHeader(parameters: [
            "typ": "openid4vci-proof+jwt",
            "alg": algorithm.name,
            "jwk": jwk.toDictionary()
        ])
        let payloadDictionary: [String: Any] = [
            JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
			JWTClaimNames.audience: "https://localhost:8080/"
        ]
        let payload = Payload(try payloadDictionary.toThrowingJSONData())
        
        guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
            throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
        }
        let signer = try await createSigner(
            with: header,
            and: payload,
            for: privateKey,
            and: signatureAlgorithm
        )
        let jws = try JWS(
            header: header,
            payload: payload,
            signer: signer
        )
        
        return jws.compactSerializedString
    }
    
    private func createSigner(
        with header: JWSHeader,
        and payload: Payload,
        for privateKey: SigningKeyProxy,
        and signatureAlgorithm: SignatureAlgorithm
    ) async throws -> Signer {
        switch privateKey {
        case .secKey(let secKey):
            guard let secKeySigner = Signer(
                signatureAlgorithm: signatureAlgorithm,
                key: secKey)
            else {
                throw ValidationError.error(reason: "Failed creation of the secKey signer")
            }
             return secKeySigner
        case .custom(let customAsyncSigner):
            let headerData = header as DataConvertible
            let signature = try await customAsyncSigner.signAsync(
              headerData.data(),
              payload.data()
            )
            
            let customSigner = CustomSigner(
                signature: signature,
                algorithm: signatureAlgorithm
            )
            return Signer(customSigner: customSigner)
        }
    }
}

class CustomSigner: JOSESwift.SignerProtocol {
    var algorithm: JOSESwift.SignatureAlgorithm
    let signature: Data
    
    init(signature: Data, algorithm: JOSESwift.SignatureAlgorithm) {
        self.algorithm = algorithm
        self.signature = signature
    }
    
    func sign(_ signingInput: Data) throws -> Data {
        return signature
    }
}
