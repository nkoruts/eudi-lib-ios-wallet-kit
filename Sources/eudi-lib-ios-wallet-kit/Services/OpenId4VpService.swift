 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */
 

import Foundation
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SiopOpenID4VP
import JOSESwift
import Logging

/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP – Draft 18 specification
class OpenId4VpService: PresentationService {
	var status: TransferStatus = .initialized
	var openid4VPlink: String
	var docs: [DeviceResponse]!
	var iaca: [SecCertificate]!
	var devicePrivateKey: CoseKeyPrivate!
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var walletConf: WalletOpenId4VPConfiguration!
	var flow: FlowType

	init(parameters: [String: Any], qrCode: Data, openId4VpVerifierApiUri: String?) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		guard let cfg = Self.getWalletConf(verifierApiUrl: openId4VpVerifierApiUri ?? "http://localhost:8080") else {
			throw PresentationSession.makeError(str: "INVALID_WALLET_CONFIGURATION")
		}
		walletConf = cfg
		guard let (docs, devicePrivateKey, iaca) = MdocHelpers.initializeData(parameters: parameters) else {
			throw PresentationSession.makeError(str: "MDOC_DATA_NOT_AVAILABLE")
		}
		self.docs = docs; self.devicePrivateKey = devicePrivateKey; self.iaca = iaca
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: walletConf)
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
	}
	
	func startQrEngagement() async throws -> Data? { nil }
	
	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
	func receiveRequest() async throws -> [String: Any] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
			switch try await siopOpenId4Vp.authorize(url: openid4VPURI)  {
			case .notSecured(data: _):
				throw PresentationSession.makeError(str: "Not secure request received.")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
					self.presentationDefinition = vp.presentationDefinition
					let items = parsePresentationDefinition(vp.presentationDefinition)
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					return [UserRequestKeys.valid_items_requested.rawValue: items]
				default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
				}
			}
	}
	
	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws {
		guard let pd = presentationDefinition, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpToken(nil, pd, resolved)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend)")
		guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, deviceResponses: docs, selectedItems: itemsToSend) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		// Obtain consent
		let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
		try await SendVpToken(vpTokenStr, pd, resolved)
	}
	
	fileprivate func SendVpToken(_ vpTokenStr: String?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData) async throws {
		let consent: ClientConsent = if let vpTokenStr { .vpToken(vpToken: vpTokenStr, presentationSubmission: .init(id: pd.id, definitionID: pd.id, descriptorMap: [])) } else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: walletConf)
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
	}
	
	/// Parse mDoc request from presentation definition (Presentation Exchange 2.0.0 protocol)
	func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition) -> RequestItems? {
		guard let fieldConstraints = presentationDefinition.inputDescriptors.first?.constraints.fields else { return nil }
		guard let docType = fieldConstraints.first(where: {$0.paths.first == "$.mdoc.doctype" })?.filter?["const"] as? String else { return nil }
		guard let namespace = fieldConstraints.first(where: {$0.paths.first == "$.mdoc.namespace" })?.filter?["const"] as? String else { return nil }
		let requestedFields = fieldConstraints.filter { $0.intentToRetain != nil }.compactMap { $0.paths.first?.replacingOccurrences(of: "$.mdoc.", with: "") }
		return [docType:[namespace:requestedFields]]
	}
	
	/// OpenId4VP wallet configuration
	static func getWalletConf(verifierApiUrl: String) -> WalletOpenId4VPConfiguration? {
	let verifierMetaData = PreregisteredClient(clientId: "Verifier", jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUrl)/wallet/public-keys.json")!))
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
			  let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		var res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), idTokenTTL: 10 * 60, presentationDefinitionUriSupported: true, signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])], vpFormatsSupported: [])
		return res
	}

}
