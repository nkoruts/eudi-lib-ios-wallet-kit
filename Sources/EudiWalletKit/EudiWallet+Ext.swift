//
//  EudiWallet+Ext.swift
//  EudiWalletKit
//
//  Created by Nikita Koruts on 23.04.2025.
//

import Foundation
import OpenID4VCI

extension EudiWallet {
	public func issueDocument(parameters: DocIssuanceModel, metadata: CredentialIssuerMetadata, issueCredentials: ((DocIssuanceRequest) async throws -> [CredentialIssuanceResponse])) async throws {
		let docType = parameters.docType
		var openId4VCIServices: [OpenId4VCIService] = []
		var proofs: [DocIssuanceRequestProof] = []
		var configurations: [CredentialConfiguration] = []
		for dataFormat in parameters.dataFormats {
			let docTypeIdentifier: DocTypeIdentifier = .identifier(dataFormat.identifier)
			let openId4VCIService = try await prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: nil, keyOptions: nil, disablePrompt: false, promptMessage: nil)
			openId4VCIServices.append(openId4VCIService)
			let credentialConfiguration = try await openId4VCIService.getCredentialIssuingConfiguration(docTypeIdentifier: docTypeIdentifier, metadata: metadata)
			let securityKeys = try await openId4VCIService.initSecurityKeys(algSupported: Set(credentialConfiguration.credentialSigningAlgValuesSupported))
			guard let proof = try await securityKeys.first?.getProof() else { continue }
			let requestProof = DocIssuanceRequestProof(jwt: proof, proofType: "jwk", format: dataFormat.format.description)
			proofs.append(requestProof)
			configurations.append(credentialConfiguration)
		}
		let issuanceRequest = DocIssuanceRequest(doctype: docType, proofs: proofs)
		let issuanceResponse = try await issueCredentials(issuanceRequest)
		for (index, response) in issuanceResponse.enumerated() {
			let openId4VCIService = openId4VCIServices[index]
			let issuanceOutcome = try await handleIssuanceResponse(response, configuration: configurations[index], openId4VCIService: openId4VCIService)
			let format = parameters.dataFormats[index].format
			_ = try await finalizeIssuing(issueOutcome: issuanceOutcome, docType: docType, format: format, issueReq: openId4VCIService.issueReq, openId4VCIService: openId4VCIService)
		}
	}
	
	private func handleIssuanceResponse(_ issuanceResponse: CredentialIssuanceResponse, configuration: CredentialConfiguration, openId4VCIService: OpenId4VCIService) async throws -> IssuanceOutcome {
		guard let result = issuanceResponse.credentialResponses.first else { throw WalletError(description: "No credential response results available") }
		guard case .issued(_, let credential, _, _) = result else { throw WalletError(description: "Unsupported document status (deferred) ") }
		return try await openId4VCIService.handleCredentialResponse(credentials: [credential], format: nil, configuration: configuration)
	}
}
