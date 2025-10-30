//
//  OpenId4VCIService+Ext.swift
//  EudiWalletKit
//
//  Created by Nikita Koruts on 12.08.2025.
//

import Foundation
import OpenID4VCI

extension OpenId4VCIService {
	func getCredentialIssuingConfiguration(docTypeIdentifier: DocTypeIdentifier, metadata: CredentialIssuerMetadata) async throws -> CredentialConfiguration {
		guard let credentialIssuerURL = config.credentialIssuerURL else { throw WalletError(description: "credentialIssuerURL not found") }
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let credentialConfiguration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metadata.display, credentialsSupported: metadata.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metadata.batchCredentialIssuance)
		return credentialConfiguration
	}
}
