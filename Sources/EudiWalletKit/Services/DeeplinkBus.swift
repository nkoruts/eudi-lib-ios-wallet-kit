//
//  DeeplinkBus.swift
//  EudiWalletKit
//

import Foundation

public enum DeeplinkEvent: Sendable {
	case url(URL)
}

public actor DeeplinkBus {
	public static let shared = DeeplinkBus()

	private var continuation: AsyncStream<DeeplinkEvent>.Continuation?

	public lazy var stream: AsyncStream<DeeplinkEvent> = {
		AsyncStream { cont in
			self.continuation = cont
		}
	}()

	public func publish(_ url: URL) {
		continuation?.yield(.url(url))
	}
}