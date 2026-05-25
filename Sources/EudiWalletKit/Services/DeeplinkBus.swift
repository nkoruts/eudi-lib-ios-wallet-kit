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

	private var subscribers: [UUID: AsyncStream<DeeplinkEvent>.Continuation] = [:]

	private init() {}

	public func subscribe() -> AsyncStream<DeeplinkEvent> {
		let id = UUID()
		return AsyncStream(bufferingPolicy: .unbounded) { continuation in
			subscribers[id] = continuation
			continuation.onTermination = { [weak self] _ in
				Task { await self?.removeSubscriber(id) }
			}
		}
	}

	private func removeSubscriber(_ id: UUID) {
		subscribers[id] = nil
	}

	public func publish(_ url: URL) {
		for continuation in subscribers.values {
			continuation.yield(.url(url))
		}
	}
}
