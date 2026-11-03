"""Match a message to a Loghub-style template.

`<*>` is the only wildcard and may match an empty span (Linux_2k E29 has an
empty `()`). Among full-string matches, the template with the most literal
characters wins, then the fewest wildcards, then the smallest numeric suffix.
"""

import re

_EVENT_ID_NUMBER = re.compile(r"^[A-Za-z]+(\d+)$")


class TemplateMatcher:
    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._items: list[tuple[tuple[int, int, int, str], str, str, re.Pattern[str]]] = []
        for event_id, template in pairs:
            parts = template.split("<*>")
            pattern = "^" + "(.*?)".join(re.escape(part) for part in parts) + "$"
            literal = sum(len(part) for part in parts)
            wildcards = template.count("<*>")
            number_match = _EVENT_ID_NUMBER.match(event_id)
            number = int(number_match.group(1)) if number_match else 10**9
            score = (literal, -wildcards, -number, event_id)
            self._items.append((score, event_id, template, re.compile(pattern)))

    def match(self, content: str) -> tuple[str, str] | None:
        best_score: tuple[int, int, int, str] | None = None
        best: tuple[str, str] | None = None
        for score, event_id, template, pattern in self._items:
            if pattern.fullmatch(content):
                if best_score is None or score > best_score:
                    best_score = score
                    best = (event_id, template)
        return best
