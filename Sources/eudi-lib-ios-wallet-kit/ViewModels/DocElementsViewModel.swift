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

/// View model used in SwiftUI for presentation request elements
public struct DocElementsViewModel: Identifiable {
	public var id: String { docType }
	public let docType: String
	public var isEnabled: Bool
	public var elements: [ElementViewModel]
}

func fluttenItemViewModels(_ nsItems: [String:[String]], valid isEnabled: Bool) -> [ElementViewModel] {
	nsItems.map { k,v in nsItemsToViewModels(k,v, isEnabled) }.flatMap {$0}
}

func nsItemsToViewModels(_ ns: String, _ items: [String], _ isEnabled: Bool) -> [ElementViewModel] {
	items.map { ElementViewModel(nameSpace: ns, elementIdentifier:$0, isEnabled: isEnabled) }
}

extension RequestItems {
	func toDocElementViewModels(valid: Bool) -> [DocElementsViewModel] {
		map { docType,nsItems in DocElementsViewModel(docType: docType, isEnabled: valid, elements: fluttenItemViewModels(nsItems, valid: valid)) }
	}
}

extension Array where Element == DocElementsViewModel {
	public var items: RequestItems { Dictionary(grouping: self, by: \.docType).mapValues { $0.first!.elements.filter(\.isSelected).nsDictionary } }

	func merging(with other: Self) -> Self {
		var res = Self()
		for otherDE in other {
			if let exist = first(where: { $0.docType == otherDE.docType})	{
				let newElements = (exist.elements + otherDE.elements).sorted(by: { $0.isEnabled && $1.isDisabled })
				res.append(DocElementsViewModel(docType: exist.docType, isEnabled: exist.isEnabled, elements: newElements))
			}
			else { res.append(otherDE) }
		}
		return res
	}
}

public struct ElementViewModel: Identifiable {
	public var id: String { "\(nameSpace)_\(elementIdentifier)" }
	public let nameSpace: String
	public let elementIdentifier: String
	public var isEnabled: Bool
	public var isDisabled: Bool { !isEnabled }
	public var isSelected = true
}

extension Array where Element == ElementViewModel {
	var nsDictionary: [String: [String]] { Dictionary(grouping: self, by: \.nameSpace).mapValues { $0.map(\.elementIdentifier)} }
}
