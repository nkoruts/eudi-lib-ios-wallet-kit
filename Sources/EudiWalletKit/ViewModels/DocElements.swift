/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import MdocDataModel18013
import MdocDataTransfer18013

public struct DocPresentInfo: Sendable {
	let docType: String
	let docDataFormat: DocDataFormat
	let displayName: String?
	let docClaims: [DocClaim]
	let typedData: DocTypedData
}

public enum DocElements: Identifiable, Sendable {
	case msoMdoc(MsoMdocElements)
	case sdJwt(SdJwtElements)

	public var id: String {
	 switch self {
	 case .msoMdoc(let element): return element.id
	 case .sdJwt(let element): return element.id
	 }
	}

	public var msoMdoc: MsoMdocElements? {
		if case .msoMdoc(let mdoc) = self { return mdoc } else { return nil }
	}

	public var isMsoMdoc: Bool {
		if case .msoMdoc(_) = self { return true } else { return false }
	}
	public var isSdJwt: Bool {
		if case .sdJwt(_) = self { return true } else { return false }
	}
	public var docTypeOrVct: String {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.docType
		case .sdJwt(let sdJwt): return sdJwt.vct
		}
	}
	public var isEnabled: Bool {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.isEnabled
		case .sdJwt(let sdJwt): return sdJwt.isEnabled
		}
	}
	public var docId: String {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.docId
		case .sdJwt(let sdJwt): return sdJwt.docId
		}
	}
	public var selectedItemsDictionary: [String: [RequestItem]] {
		switch self {
		case .msoMdoc(let mdoc): return mdoc.selectedItemsDictionary
		case .sdJwt(let sdJwt): return sdJwt.selectedItemsDictionary
		}
	}
}

/// Element collection for mso-mdoc document
/// Used for disclosure of mdoc elements
public final class MsoMdocElements: Identifiable, @unchecked Sendable {
	public init(docId: String, docType: String, displayName: String? = nil, isEnabled: Bool = true, nameSpacedElements: [NameSpacedElements]) {
		self.docId = docId
		self.docType = docType
		self.displayName = displayName
		self.isEnabled = isEnabled
		self.nameSpacedElements = nameSpacedElements
	}

	public var id: String { docId }
	/// Document identifier
	public var docId: String
	/// Document type
	public let docType: String
	/// Display name of the document
	public let displayName: String?
	/// Indicates whether the document is enabled (false if requested but not available)
	public var isEnabled: Bool = true
	/// Collection of elements grouped by namespace
	public var nameSpacedElements: [NameSpacedElements]
	/// Dictionary of selected items grouped by namespace
	public var selectedItemsDictionary: [String: [RequestItem]] {
		Dictionary(grouping: nameSpacedElements, by: \.nameSpace).filter { $1.first!.elements.count > 0}.mapValues {ne in ne.first!.elements.filter(\.isSelected).map(\.requestItem)}
	}
}

public final class SdJwtElements: Identifiable, @unchecked Sendable {
	internal init(docId: String, vct: String, displayName: String? = nil, isEnabled: Bool = true, sdJwtElements: [SdJwtElement]) {
		self.docId = docId
		self.vct = vct
		self.displayName = displayName
		self.isEnabled = isEnabled
		self.sdJwtElements = sdJwtElements
	}

	public var id: String { docId }
	public var docId: String
	public let vct: String
	public let displayName: String?
	public var isEnabled: Bool = true
	public var sdJwtElements: [SdJwtElement]

	public var selectedItemsDictionary: [String: [RequestItem]] {
		["": sdJwtElements.filter(\.isSelected).map(\.requestItem)]
	}
}

extension IssuerSigned {
	func extractMsoMdocElements(docId: String, docType: String, displayName: String?, docClaims: [DocClaim], itemsRequested: [NameSpace: [RequestItem]]) -> MsoMdocElements {
		MsoMdocElements(docId: docId, docType: docType, displayName: displayName, nameSpacedElements: itemsRequested.compactMap { ns, requestItems in
			extractNameSpacedElements(docType: docType, ns: ns, docClaims: docClaims, requestItems: requestItems)
		})
	}

	func extractNameSpacedElements(docType: String, ns: String, docClaims: [DocClaim], requestItems: [RequestItem]) -> NameSpacedElements? {
		guard let issuedItems = issuerNameSpaces?[ns] else { return nil }
		let mandatoryElementKeys = MsoMdocElements.getMandatoryElementKeys(docType: docType, ns: ns)
		return NameSpacedElements(nameSpace: ns, elements: requestItems.map { $0.extractMsoMdocElement(ns: ns, nsItems: issuedItems, docClaims: docClaims, isMandatory: mandatoryElementKeys.contains($0.rootIdentifier)) })
	}
}

extension RequestItem {
	func extractMsoMdocElement(ns: String, nsItems: [IssuerSignedItem], docClaims: [DocClaim], isMandatory: Bool) -> MsoMdocElement {
		let issuedElement = nsItems.first { $0.elementIdentifier == rootIdentifier }
		let stringValue = issuedElement?.description
		let docClaim = docClaims.first { $0.namespace == ns && $0.name == rootIdentifier }
		return MsoMdocElement(elementIdentifier: elementIdentifier, displayName: rootDisplayName ?? docClaim?.displayName ?? rootIdentifier, isOptional: !isMandatory, intentToRetain: intentToRetain ?? false, stringValue: stringValue, docClaim: docClaim, isValid: issuedElement != nil)
	}
}

extension MsoMdocElements {

	static func getMandatoryElementKeys(docType: String, ns: String) -> [String] {
		switch (docType, ns) {
		case (IsoMdlModel.isoDocType, IsoMdlModel.isoNamespace):
			return IsoMdlModel.isoMandatoryElementKeys
		case (EuPidModel.euPidDocType, "eu.europa.ec.eudi.pid.1"):
			return EuPidModel.pidMandatoryElementKeys
		default:
			return []
		}
	}
}

extension Array where Element == DocElements {
	public var items: RequestItems { Dictionary(grouping: self, by: \.docId).mapValues { $0.first!.selectedItemsDictionary } }
}


public final class NameSpacedElements: Identifiable, @unchecked Sendable {
	public init(nameSpace: String, elements: [MsoMdocElement]) {
		self.nameSpace = nameSpace
		self.elements = elements
	}
	public var id: String { nameSpace }
	public let nameSpace: String
	public var elements: [MsoMdocElement]
}

public final class MsoMdocElement: Identifiable, @unchecked Sendable {
	public init(elementIdentifier: String, displayName: String, isOptional: Bool, intentToRetain: Bool = false, stringValue: String?, docClaim: DocClaim?, isValid: Bool, isSelected: Bool = true) {
		self.elementIdentifier = elementIdentifier
		self.displayName = displayName
		self.isOptional = isOptional
		self.intentToRetain = intentToRetain
		self.stringValue = stringValue
		self.docClaim = docClaim
		self.isValid = isValid
		self.isSelected = isSelected
	}

	public var id: String { elementIdentifier }
	/// path to locate the element
	public let elementIdentifier: String
	// display names of the component paths
	public let displayName: String
	public let isOptional: Bool
	public var intentToRetain: Bool = false
	public let stringValue: String?
	public let docClaim: DocClaim?
	public var isValid: Bool
	public var isSelected = true

	public var requestItem: RequestItem {
		RequestItem(elementPath: [elementIdentifier], displayNames: [displayName], intentToRetain: intentToRetain, isOptional: isOptional)
	}
}

public struct SdJwtElement: Identifiable, Sendable {
	public init(elementPath: [String], displayNames: [String?], isOptional: Bool, intentToRetain: Bool = false, isEnabled: Bool, isSelected: Bool = true) {
		self.elementPath = elementPath
		self.displayNames = displayNames
		self.isOptional = isOptional
		self.intentToRetain = intentToRetain
		self.isEnabled = isEnabled
		self.isSelected = isSelected
	}

	public var id: String { elementPath.joined(separator: ".") }
	/// path to locate the element
	public let elementPath: [String]
	// display names of the component paths
	public let displayNames: [String?]
	public let isOptional: Bool
	public let intentToRetain: Bool
	public var isEnabled: Bool
	public var isSelected = true

	public var requestItem: RequestItem {
		RequestItem(elementPath: elementPath, displayNames: displayNames, intentToRetain: intentToRetain, isOptional: isOptional)
	}
}


