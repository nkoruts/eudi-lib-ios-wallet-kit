//
//  DocIssuanceModel.swift
//  EudiWalletKit
//
//  Created by Nikita Koruts on 26.03.2025.
//

import OpenID4VCI
import MdocDataModel18013

public struct DocIssuanceModel {
    public let docType: String
    public let dataFormats: [DocIssuanceDataFormat]
}

public struct DocIssuanceDataFormat {
    public let format: DocDataFormat
    public let identifier: String
}

public struct DocIssuanceRequest: Codable {
    public let doctype: String
    public let proofs: [DocIssuanceRequestProof]
}

public struct DocIssuanceRequestProof: Codable {
    public let jwt: String
    public let proofType: String
    public let format: String
}
