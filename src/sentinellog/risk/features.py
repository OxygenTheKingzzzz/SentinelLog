"""Feature fitting. Vocabularies and frequencies are fit on the training groups only."""

import math

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import hour_cycle

STRUCTURAL = (
    "char_len",
    "token_count",
    "digit_ratio",
    "severity_rank",
    "has_pid",
    "hour_sin",
    "hour_cos",
    "template_rarity",
    "component_rarity",
)


class FeatureEncoder:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.vectorizer: TfidfVectorizer | None = None
        self.svd: TruncatedSVD | None = None
        self.template_counts: dict[str, int] = {}
        self.component_counts: dict[str, int] = {}
        self.n_train = 0
        self.structural_names = list(STRUCTURAL)
        self.svd_names: list[str] = []

    def fit(self, train: list[Example]) -> None:
        self.n_train = len(train)
        self.template_counts = {}
        self.component_counts = {}
        for item in train:
            self.template_counts[item.group_key] = self.template_counts.get(item.group_key, 0) + 1
            self.component_counts[item.component] = self.component_counts.get(item.component, 0) + 1
        self.vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),
            min_df=2,
            token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|E\d+",
        )
        texts = [item.content for item in train]
        try:
            matrix = self.vectorizer.fit_transform(texts)
        except ValueError:
            self.vectorizer.set_params(min_df=1)
            matrix = self.vectorizer.fit_transform(texts)
        n_components = min(16, matrix.shape[0] - 1, matrix.shape[1] - 1)
        self.svd = None
        self.svd_names = []
        if n_components >= 2:
            self.svd = TruncatedSVD(n_components=n_components, random_state=self.seed)
            self.svd.fit(matrix)
            self.svd_names = [f"text_component_{index}" for index in range(n_components)]

    def vocabulary(self) -> set[str]:
        if self.vectorizer is None:
            return set()
        return set(self.vectorizer.vocabulary_)

    def sparse_text(self, examples: list[Example]):
        if self.vectorizer is None:
            raise RuntimeError("encoder is not fit")
        return self.vectorizer.transform([item.content for item in examples])

    def structural(self, examples: list[Example]) -> np.ndarray:
        rows = [self._structural_row(item) for item in examples]
        return np.asarray(rows, dtype=np.float64)

    def dense(self, examples: list[Example]) -> np.ndarray:
        base = self.structural(examples)
        if self.svd is None or self.vectorizer is None:
            return base
        projected = self.svd.transform(self.sparse_text(examples))
        return np.hstack([base, projected])

    def feature_names(self) -> list[str]:
        return self.structural_names + self.svd_names

    def _rarity(self, counts: dict[str, int], key: str) -> float:
        seen = counts.get(key, 0)
        return -math.log((seen + 1) / (self.n_train + 1))

    def _structural_row(self, item: Example) -> list[float]:
        text = item.content
        digits = sum(character.isdigit() for character in text)
        hour_sin, hour_cos = hour_cycle(item.timestamp)
        return [
            float(len(text)),
            float(len(text.split())),
            float(digits) / float(len(text) or 1),
            float(item.severity_rank),
            0.0 if item.pid is None else 1.0,
            hour_sin,
            hour_cos,
            self._rarity(self.template_counts, item.group_key),
            self._rarity(self.component_counts, item.component),
        ]
