/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import OpenID4VCI
import Testing
@testable import EudiWalletKit

private struct MissingSignedMetadataFetcher: MetadataFetching {
	func fetchMetadata(
		url: URL,
		policy: IssuerMetadataPolicy,
		issuerId: CredentialIssuerId
	) async -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError> {
		.failure(.missingSignedMetadata)
	}
}

/// Records every request so tests can assert how many were made and which `Accept` header
/// (and therefore which `IssuerMetadataPolicy`) the issuer metadata fetch used.
private actor CountingOfferNetworking: NetworkingProtocol {
	private(set) var requests: [URLRequest] = []
	private let issuer: String

	init(issuer: String = "https://unused.example") {
		self.issuer = issuer
	}

	var requestCount: Int { requests.count }

	func acceptHeader(ofRequestContaining fragment: String) -> String? {
		requests.first { $0.url?.absoluteString.contains(fragment) == true }?.value(forHTTPHeaderField: "Accept")
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await data(for: URLRequest(url: url))
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		requests.append(request)
		let url = try #require(request.url)
		let body: Data
		if url.absoluteString.contains("/.well-known/openid-credential-issuer") {
			let fixture = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
			let text = try #require(String(data: fixture, encoding: .utf8))
			body = Data(text.replacingOccurrences(of: "https://demo.pid-provider.bundesdruckerei.de", with: issuer).utf8)
		} else if url.absoluteString.contains("/.well-known/oauth-authorization-server") {
			body = try JSONEncoder().encode(AuthorizationServerMetadata(issuer: issuer, tokenEndpoint: issuer + "/token"))
		} else {
			throw URLError(.cannotConnectToHost)
		}
		let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
		return (body, response)
	}
}

/// Serializes tests touching `OpenId4VciService`'s process-wide metadata cache across suites:
/// `EudiWallet.resolveOfferUrlDocTypes` clears it, and `.serialized` only applies within one suite.
actor MetadataCacheTestLock {
	static let shared = MetadataCacheTestLock()
	private var isHeld = false
	private var waiters: [CheckedContinuation<Void, Never>] = []

	func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async rethrows -> T {
		await acquire()
		defer { release() }
		return try await body()
	}

	private func acquire() async {
		guard isHeld else { isHeld = true; return }
		await withCheckedContinuation { waiters.append($0) }
	}

	private func release() {
		if waiters.isEmpty { isHeld = false } else { waiters.removeFirst().resume() }
	}
}

private enum OfferFixture {
	static func uniqueIssuer(_ label: String) -> String {
		"https://\(label)-\(UUID().uuidString.lowercased()).example"
	}

	static func encoded(_ value: String) -> String {
		value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
	}

	static func offerJson(issuer: String) -> String {
		#"{"credential_issuer":"\#(issuer)","credential_configuration_ids":["pid-sd-jwt"]}"#
	}

	static func uri(_ parameters: (name: String, value: String)...) -> String {
		"openid-credential-offer://?" + parameters.map { "\($0.name)=\(encoded($0.value))" }.joined(separator: "&")
	}

	/// A wallet whose own default policy requires signed metadata, so the `.ignoreSigned`
	/// policy of the registered issuer is observably different.
	static func wallet(registeredIssuer: String, networking: any NetworkingProtocol) throws -> EudiWallet {
		#if canImport(EudiEtsi1196x2)
		let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), requireSignedMetadata: true)
		#else
		let trustConfig = TrustConfiguration(rootIaca: [], requireSignedMetadata: true)
		#endif
		return try EudiWallet(
			eudiWalletConfig: EudiWalletConfiguration(serviceName: "test.credentialOffer.\(UUID().uuidString)"),
			trustConfig: trustConfig,
			storageService: TestDataStorageService(),
			openID4VciConfigurations: [
				registeredIssuer: OpenId4VciConfiguration(credentialIssuerURL: registeredIssuer, issuerMetadataPolicy: .ignoreSigned)
			],
			networking: networking
		)
	}

	static func expectOfferResolutionFailed(_ body: () async throws -> Void) async {
		do {
			try await body()
			Issue.record("Expected the offer to be rejected")
		} catch let error as WalletError {
			#expect(error.code == .offerResolutionFailed)
		} catch {
			Issue.record("Expected WalletError, got \(error)")
		}
	}
}

@Suite("Credential offer error recovery")
struct CredentialOfferErrorRecoveryTests {
	@Test("recovers the concrete issuer metadata error")
	func recoversMetadataError() async {
		let source = CredentialOfferRequest.passByValue(metaData: """
			{
			  "credential_issuer": "https://issuer.example.com",
			  "credential_configuration_ids": ["pid"]
			}
			""")
		let flattened = ValidationError.error(reason: "Invalid credential metadata")
		let resolver = CredentialIssuerMetadataResolver(fetcher: MissingSignedMetadataFetcher())

		let recovered = await source.recoverMetadataError(
			from: flattened,
			policy: .ignoreSigned,
			fetcher: Fetcher<CredentialOfferRequestObject>(),
			metadataResolver: resolver
		)

		guard let metadataError = recovered as? CredentialIssuerMetadataError else {
			Issue.record("Expected CredentialIssuerMetadataError, got \(type(of: recovered))")
			return
		}
		guard case .missingSignedMetadata = metadataError else {
			Issue.record("Expected missingSignedMetadata, got \(metadataError)")
			return
		}
		#expect(CredentialOfferRequest.metadataErrorDescription(for: recovered) == "Credential issuer metadata is not signed")
	}

	@Test("leaves unrelated resolver errors unchanged")
	func preservesUnrelatedError() async {
		let original = ValidationError.error(reason: "Invalid authorization metadata")
		let recovered = await CredentialOfferRequest.passByValue(metaData: "{}").recoverMetadataError(
			from: original,
			policy: .ignoreSigned,
			fetcher: Fetcher<CredentialOfferRequestObject>(),
			metadataResolver: CredentialIssuerMetadataResolver(fetcher: MissingSignedMetadataFetcher())
		)

		#expect(recovered.localizedDescription == original.localizedDescription)
	}

	// MARK: - Repeated offer parameters (OID4VCI §4.1, OID4VCI §13.5)

	@Test("AC1/AC4: repeated credential_offer yields no issuer URL, in either order")
	func extractRejectsRepeatedCredentialOffer() {
		let a = OfferFixture.offerJson(issuer: "https://a.example")
		let b = OfferFixture.offerJson(issuer: "https://b.example")
		#expect(EudiWallet.extractCredentialIssuerURL(from: OfferFixture.uri(("credential_offer", a))) == "https://a.example")
		#expect(EudiWallet.extractCredentialIssuerURL(from: OfferFixture.uri(("credential_offer", a), ("credential_offer", b))) == nil)
		#expect(EudiWallet.extractCredentialIssuerURL(from: OfferFixture.uri(("credential_offer", b), ("credential_offer", a))) == nil)
	}

	@Test("repetition is detected in the forms the library also accepts", arguments: [
		// Raw JSON, which URL(string:) percent-encodes for the library.
		#"openid-credential-offer://?credential_offer={"credential_issuer":"https://a.example"}&credential_offer={"credential_issuer":"https://b.example"}"#,
		// A percent-encoded parameter name decodes to the same name.
		"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fa.example%22%7D&credential%5Foffer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fb.example%22%7D",
		// A repeated name is rejected even when one occurrence has no value.
		"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fa.example%22%7D&credential_offer",
		// Repeated by-reference parameter next to a by-value one.
		"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fa.example%22%7D&credential_offer_uri=https%3A%2F%2Fb.example%2F1&credential_offer_uri=https%3A%2F%2Fb.example%2F2",
	])
	func extractRejectsRepetitionVariants(uri: String) {
		#expect(EudiWallet.extractCredentialIssuerURL(from: uri) == nil)
	}

	@Test("the issuer URL is the one the library parses: the value is not percent-decoded a second time")
	func extractDoesNotDecodeOfferTwice() {
		// OID4VCI §13.5: decoded twice, %22 closes the JSON string and a later key names the
		// registered issuer, while the library resolves the attacker's URL.
		let attackerIssuer = #"https://attacker.example/%22,%22credential_issuer%22:%22https://victim.example"#
		let uri = OfferFixture.uri(("credential_offer", OfferFixture.offerJson(issuer: attackerIssuer)))
		#expect(EudiWallet.extractCredentialIssuerURL(from: uri) == attackerIssuer)
	}

	@Test("AC2/AC4: two credential_offer values are rejected before any network request, in either order")
	func resolveRejectsRepeatedCredentialOffer() async throws {
		let registered = OfferFixture.uniqueIssuer("registered")
		let unregistered = OfferFixture.uniqueIssuer("unregistered")
		let a = OfferFixture.offerJson(issuer: registered)
		let b = OfferFixture.offerJson(issuer: unregistered)
		let networking = CountingOfferNetworking()
		let wallet = try OfferFixture.wallet(registeredIssuer: registered, networking: networking)

		for uri in [OfferFixture.uri(("credential_offer", a), ("credential_offer", b)), OfferFixture.uri(("credential_offer", b), ("credential_offer", a))] {
			await OfferFixture.expectOfferResolutionFailed {
				_ = try await wallet.resolveOfferUrlDocTypes(offerUri: uri, authFlowRedirectionURI: nil)
			}
		}
		#expect(await networking.requestCount == 0)
	}

	@Test("AC3/AC4: two credential_offer_uri values are rejected before any network request, in either order")
	func resolveRejectsRepeatedCredentialOfferUri() async throws {
		let networking = CountingOfferNetworking()
		let wallet = try OfferFixture.wallet(registeredIssuer: OfferFixture.uniqueIssuer("registered"), networking: networking)
		let a = "https://a.example/offer"
		let b = "https://b.example/offer"

		for uri in [OfferFixture.uri(("credential_offer_uri", a), ("credential_offer_uri", b)), OfferFixture.uri(("credential_offer_uri", b), ("credential_offer_uri", a))] {
			await OfferFixture.expectOfferResolutionFailed {
				_ = try await wallet.resolveOfferUrlDocTypes(offerUri: uri, authFlowRedirectionURI: nil)
			}
		}
		#expect(await networking.requestCount == 0)
	}

	@Test("issueDocumentsByOfferUrl rejects repeated offer parameters before any network request")
	func issueRejectsRepeatedParameters() async throws {
		let registered = OfferFixture.uniqueIssuer("registered")
		let networking = CountingOfferNetworking()
		let wallet = try OfferFixture.wallet(registeredIssuer: registered, networking: networking)
		let offer = OfferFixture.offerJson(issuer: registered)

		for uri in [OfferFixture.uri(("credential_offer", offer), ("credential_offer", offer)), OfferFixture.uri(("credential_offer_uri", "https://a.example/1"), ("credential_offer_uri", "https://a.example/2"))] {
			await OfferFixture.expectOfferResolutionFailed {
				_ = try await wallet.issueDocumentsByOfferUrl(offerUri: uri, docTypes: [])
			}
		}
		#expect(await networking.requestCount == 0)
	}

	@Test("AC5: a single credential_offer for a registered issuer resolves under that issuer's policy")
	func singleOfferUsesRegisteredIssuerPolicy() async throws {
		try await MetadataCacheTestLock.shared.withLock {
			let registered = OfferFixture.uniqueIssuer("registered")
			let networking = CountingOfferNetworking(issuer: registered)
			let wallet = try OfferFixture.wallet(registeredIssuer: registered, networking: networking)
			let uri = OfferFixture.uri(("credential_offer", OfferFixture.offerJson(issuer: registered)))

			let model = try await wallet.resolveOfferUrlDocTypes(offerUri: uri, authFlowRedirectionURI: nil)

			#expect(model.docModels.count == 1)
			// .ignoreSigned asks for JSON; the wallet default (.requireSigned) would ask for application/jwt.
			#expect(await networking.acceptHeader(ofRequestContaining: "/.well-known/openid-credential-issuer") == "application/json")
		}
	}
}
