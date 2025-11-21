//
//  EudiWallet+Ext.swift
//  EudiWalletKit
//
//  Created by Nikita Koruts on 23.04.2025.
//

import Foundation
import OpenID4VCI
import MdocDataModel18013

extension EudiWallet {
	public func issueDocument(parameters: DocIssuanceModel, metadata: CredentialIssuerMetadata, credentialOptions: CredentialOptions, issueCredentials: ((DocIssuanceRequest) async throws -> [CredentialIssuanceResponse])) async throws {
		let docType = parameters.docType
		var vciServices: [OpenId4VCIService] = []
		var proofs: [DocIssuanceRequestProof] = []
		var publicKeys: [Data] = []
		var configurations: [CredentialConfiguration] = []
		for dataFormat in parameters.dataFormats {
			let docTypeIdentifier: DocTypeIdentifier = .identifier(dataFormat.identifier)
			guard let config = openID4VciConfigurations?.values.first else { throw WalletError(description: "No VCI configurations available") }
			let vciService = try OpenId4VCIService(uiCulture: uiCulture, config: config, networking: networkingVci, storage: storage, storageService: storage.storageService)
			vciServices.append(vciService)
			try await vciService.prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: credentialOptions, keyOptions: nil, disablePrompt: false, promptMessage: nil)
			let credentialConfiguration = try await vciService.getCredentialIssuingConfiguration(docTypeIdentifier: docTypeIdentifier, metadata: metadata)
			let algSupported = Set(credentialConfiguration.credentialSigningAlgValuesSupported)
			let (bindingKeys, pblcKeys) = try await vciService.initSecurityKeys(algSupported: algSupported)
			guard let proof = try await bindingKeys.first?.getProof(), let publicKey = pblcKeys.first else { continue }
			let requestProof = DocIssuanceRequestProof(jwt: proof, proofType: "jwk", format: dataFormat.format.value)
			proofs.append(requestProof)
			configurations.append(credentialConfiguration)
			publicKeys.append(publicKey)
		}
		let issuanceRequest = DocIssuanceRequest(doctype: docType, proofs: proofs)
		let issuanceResponse = try await issueCredentials(issuanceRequest)
		for (index, response) in issuanceResponse.enumerated() {
			guard vciServices.count > index, configurations.count > index, publicKeys.count > index else { return }
			let vciService = vciServices[index]
			let issuanceOutcome = try await handleIssuanceResponse(response, publicKey: publicKeys[index], configuration: configurations[index], openId4VCIService: vciService)
			let format = parameters.dataFormats[index].format
			_ = try await vciService.finalizeIssuing(issueOutcome: issuanceOutcome, docType: docType, format: format, issueReq: vciService.issueReq)
		}
	}
	
	private func handleIssuanceResponse(_ issuanceResponse: CredentialIssuanceResponse, publicKey: Data, configuration: CredentialConfiguration, openId4VCIService: OpenId4VCIService) async throws -> IssuanceOutcome {
		guard let result = issuanceResponse.credentialResponses.first else { throw WalletError(description: "No credential response results available") }
		guard case .issued(_, let credential, _, _) = result else { throw WalletError(description: "Unsupported document status (deferred) ") }
		return try await openId4VCIService.handleCredentialResponse(credentials: [credential], publicKeys: [publicKey], format: nil, configuration: configuration)
	}
}
