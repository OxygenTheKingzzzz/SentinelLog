"""In-process fan-out for live lines. Slow subscribers drop events instead of blocking the tail."""

import queue
import threading


class LiveHub:
    def __init__(self) -> None:
        self._subscribers: list[queue.Queue[dict[str, object]]] = []
        self._lock = threading.Lock()

    def publish(self, event: dict[str, object]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                continue

    def subscribe(self) -> queue.Queue[dict[str, object]]:
        subscriber: queue.Queue[dict[str, object]] = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[dict[str, object]]) -> None:
        with self._lock:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)


hub = LiveHub()
