"""Splits and metrics for naturally distributed log evaluation.

Groups are assigned to train, validation, and test before any row is sampled
and before a vectorizer, forest, or threshold is fit. Validation chooses the
decision threshold. The test set is scored once.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.model_selection import train_test_split

TRAIN_FRACTION = 0.60
VAL_FRACTION = 0.20
JACCARD_NEAR = 0.80
JACCARD_RELATED = 0.50


@dataclass
class GroupStat:
    key: str
    signature: str
    normal: int = 0
    anomaly: int = 0
    earliest: datetime | None = None
    latest: datetime | None = None
    timed: int = 0

    @property
    def size(self) -> int:
        return self.normal + self.anomaly

    @property
    def majority(self) -> str:
        if self.anomaly > 0 and self.anomaly >= self.normal:
            return "anomaly"
        return "normal"


@dataclass
class Catalog:
    groups: dict[str, GroupStat] = field(default_factory=dict)
    severity_counts: dict[int, list[int]] = field(default_factory=dict)
    alert_token_in_body: int = 0
    anomaly_rows: int = 0
    identifier_in_features: int = 0
    rows_seen: int = 0
    parsed: int = 0
    skipped: int = 0

    def observe(
        self,
        *,
        key: str,
        signature: str,
        label: str,
        timestamp: datetime | None,
        severity: int | None = None,
    ) -> None:
        stat = self.groups.get(key)
        if stat is None:
            stat = GroupStat(key=key, signature=_signature(signature))
            self.groups[key] = stat
        if label == "anomaly":
            stat.anomaly += 1
            self.anomaly_rows += 1
        else:
            stat.normal += 1
        if timestamp is not None:
            stat.timed += 1
            if stat.earliest is None or timestamp < stat.earliest:
                stat.earliest = timestamp
            if stat.latest is None or timestamp > stat.latest:
                stat.latest = timestamp
        if severity is not None:
            bucket = self.severity_counts.setdefault(severity, [0, 0])
            bucket[1 if label == "anomaly" else 0] += 1
        self.parsed += 1


def _signature(text: str) -> str:
    """Keep both ends of a long template so a shared header is not the whole comparison."""
    if len(text) <= 500:
        return text
    return f"{text[:240]} {text[-240:]}"


def prevalence(normal: int, anomaly: int) -> float | None:
    total = normal + anomaly
    if total == 0:
        return None
    return anomaly / total


def chronological_reason(catalog: Catalog) -> str | None:
    """Return why a time split would not be a future holdout, or None when it is usable."""
    total = catalog.parsed
    timed = sum(stat.timed for stat in catalog.groups.values())
    if total == 0 or timed / total < 0.95:
        return (
            "Fewer than 95% of parsed rows have a timestamp, so a time split "
            "would not be a future holdout."
        )
    moments = [stat.earliest for stat in catalog.groups.values() if stat.earliest is not None]
    if len(moments) < 3 or min(moments) == max(moments):
        return "Template timestamps do not span more than one instant."
    return None


def assign_splits(
    catalog: Catalog,
    *,
    mode: str,
    seed: int,
    train_fraction: float = TRAIN_FRACTION,
    val_fraction: float = VAL_FRACTION,
) -> dict[str, object]:
    """Assign every template group to one side. No group is copied across sides."""
    keys = sorted(catalog.groups)
    if len(keys) < 3:
        raise ValueError("need at least three template groups for train, validation, and test")
    if mode == "chronological":
        roles, stratified, note = _chronological_roles(catalog, keys, train_fraction, val_fraction)
        protocol = "chronological_group"
    elif mode == "stratified":
        roles, stratified, note = _stratified_roles(
            catalog, keys, seed, train_fraction, val_fraction
        )
        protocol = "realistic_group"
    else:
        raise ValueError(f"unknown split mode {mode}")
    _assert_partition(keys, roles)
    return {
        "protocol": protocol,
        "roles": roles,
        "stratified": stratified,
        "note": note,
        "counts": role_counts(catalog, roles),
        "span_overlap": _span_overlap(catalog, roles) if mode == "chronological" else None,
    }


def _assert_partition(keys: list[str], roles: dict[str, str]) -> None:
    if set(roles) != set(keys):
        raise RuntimeError("split did not assign every template group")
    if set(roles.values()) - {"train", "validation", "test"}:
        raise RuntimeError("split used an unknown role")
    if len(set(roles.values())) < 3:
        raise RuntimeError("split left a role empty")


def _stratified_roles(
    catalog: Catalog,
    keys: list[str],
    seed: int,
    train_fraction: float,
    val_fraction: float,
) -> tuple[dict[str, str], bool, str]:
    labels = [catalog.groups[key].majority for key in keys]
    counts = Counter(labels)
    holdout = 1 - train_fraction
    can_stratify = len(counts) >= 2 and all(value >= 3 for value in counts.values())
    train_keys: list[str] = []
    val_keys: list[str] = []
    test_keys: list[str] = []
    stratified = False
    if can_stratify:
        try:
            train_keys, hold_keys = train_test_split(
                keys,
                test_size=holdout,
                random_state=seed,
                stratify=labels,
            )
            hold_labels = [catalog.groups[key].majority for key in hold_keys]
            val_share = val_fraction / holdout
            if all(value >= 2 for value in Counter(hold_labels).values()):
                val_keys, test_keys = train_test_split(
                    hold_keys,
                    test_size=val_share,
                    random_state=seed,
                    stratify=hold_labels,
                )
            else:
                val_keys, test_keys = _cut(list(hold_keys), val_share, seed)
            stratified = True
        except ValueError:
            stratified = False
    if stratified:
        note = (
            "Template groups were assigned with stratification on the majority label "
            "before any sampling. Each group is in train, validation, or test only."
        )
    else:
        order = _shuffled(keys, seed)
        train_keys, val_keys, test_keys = _three_way(order, train_fraction, val_fraction)
        note = (
            "A class has fewer than three template groups, so the split is a seeded "
            "group holdout and is not stratified. Supervised training is refused when "
            "the positive class has fewer than two independent groups."
        )
    roles = _roles(train_keys, val_keys, test_keys)
    return roles, stratified, note


def _chrono_sort_key(catalog: Catalog, key: str) -> tuple[int, str, str]:
    moment = catalog.groups[key].earliest
    if moment is None:
        return (1, "", key)
    return (0, moment.isoformat(), key)


def _chronological_roles(
    catalog: Catalog,
    keys: list[str],
    train_fraction: float,
    val_fraction: float,
) -> tuple[dict[str, str], bool, str]:
    order = sorted(keys, key=lambda key: _chrono_sort_key(catalog, key))
    train_keys, val_keys, test_keys = _three_way(order, train_fraction, val_fraction)
    note = (
        "Each template is assigned by its earliest timestamp. Train is the earliest "
        "groups, validation the next block, and test the latest groups. A template "
        "that starts during training never appears in the test."
    )
    return _roles(train_keys, val_keys, test_keys), False, note


def _roles(train: list[str], validation: list[str], test: list[str]) -> dict[str, str]:
    roles: dict[str, str] = {}
    for key in train:
        roles[str(key)] = "train"
    for key in validation:
        roles[str(key)] = "validation"
    for key in test:
        roles[str(key)] = "test"
    return roles


def _shuffled(keys: list[str], seed: int) -> list[str]:
    order = list(keys)
    rng = np.random.RandomState(seed)
    rng.shuffle(order)
    return list(order)


def _three_way(
    order: list[str], train_fraction: float, val_fraction: float
) -> tuple[list[str], list[str], list[str]]:
    n_test = max(1, int(round(len(order) * (1 - train_fraction - val_fraction))))
    n_val = max(1, int(round(len(order) * val_fraction)))
    if n_test + n_val >= len(order):
        n_test = 1
        n_val = 1
    n_train = len(order) - n_val - n_test
    return order[:n_train], order[n_train : n_train + n_val], order[n_train + n_val :]


def _cut(keys: list[str], first_fraction: float, seed: int) -> tuple[list[str], list[str]]:
    del seed
    if len(keys) < 2:
        raise ValueError("need two groups to cut")
    n_first = int(round(len(keys) * first_fraction))
    n_first = min(max(n_first, 1), len(keys) - 1)
    return list(keys[:n_first]), list(keys[n_first:])


def role_counts(catalog: Catalog, roles: dict[str, str]) -> dict[str, dict[str, object]]:
    counts: dict[str, dict[str, object]] = {}
    for role in ("train", "validation", "test"):
        normal = anomaly = groups = 0
        for key, assigned in roles.items():
            if assigned != role:
                continue
            stat = catalog.groups[key]
            groups += 1
            normal += stat.normal
            anomaly += stat.anomaly
        counts[role] = {
            "groups": groups,
            "normal": normal,
            "anomaly": anomaly,
            "rows": normal + anomaly,
            "prevalence": prevalence(normal, anomaly),
        }
    population_normal = sum(stat.normal for stat in catalog.groups.values())
    population_anomaly = sum(stat.anomaly for stat in catalog.groups.values())
    counts["population"] = {
        "groups": len(catalog.groups),
        "normal": population_normal,
        "anomaly": population_anomaly,
        "rows": population_normal + population_anomaly,
        "prevalence": prevalence(population_normal, population_anomaly),
    }
    return counts


def _span_overlap(catalog: Catalog, roles: dict[str, str]) -> dict[str, object]:
    test_times = [
        catalog.groups[key].earliest
        for key, role in roles.items()
        if role == "test" and catalog.groups[key].earliest is not None
    ]
    if not test_times:
        return {"train_groups_extending_into_test": None}
    boundary = min(test_times)
    overlapping = 0
    for key, role in roles.items():
        if role != "train":
            continue
        latest = catalog.groups[key].latest
        if latest is not None and latest > boundary:
            overlapping += 1
    return {
        "test_boundary": boundary.isoformat(),
        "train_groups_extending_into_test": overlapping,
        "note": (
            "A train template can still emit lines after the first test template "
            "appears. Those later lines stay in train so the template is not copied "
            "into the test."
        ),
    }


def positive_groups(catalog: Catalog) -> int:
    return sum(1 for stat in catalog.groups.values() if stat.majority == "anomaly")


class Reservoir:
    def __init__(self, cap: int, seed: int) -> None:
        self.cap = cap
        self.rng = np.random.RandomState(seed)
        self.items: list[object] = []
        self.seen = 0

    def add(self, item: object) -> None:
        self.seen += 1
        if len(self.items) < self.cap:
            self.items.append(item)
            return
        pick = int(self.rng.randint(0, self.seen))
        if pick < self.cap:
            self.items[pick] = item


def uniform_cap(items: list, cap: int, seed: int) -> list:
    """Sample rows uniformly. Every row is already confined to one split side."""
    if len(items) <= cap:
        return list(items)
    rng = np.random.RandomState(seed)
    indexes = rng.choice(len(items), size=cap, replace=False)
    return [items[int(index)] for index in sorted(indexes)]


def _tokens(text: str) -> frozenset[str]:
    return frozenset(token for token in text.split() if token and token != "<*>")


def near_duplicate_report(
    train_keys: list[tuple[str, str]],
    test_keys: list[tuple[str, str]],
    *,
    near: float = JACCARD_NEAR,
    related: float = JACCARD_RELATED,
) -> dict[str, object]:
    """Compare normalized templates. Exact group keys are not reused as a similarity score."""
    train_sets = [(key, _tokens(signature)) for key, signature in train_keys]
    document_frequency: Counter[str] = Counter()
    for _, tokens in train_sets:
        document_frequency.update(tokens)
    n_train = max(len(train_sets), 1)
    common = {
        token
        for token, count in document_frequency.items()
        if count > max(40, int(0.02 * n_train))
    }
    index: dict[str, list[int]] = defaultdict(list)
    for position, (_, tokens) in enumerate(train_sets):
        for token in tokens - common:
            index[token].append(position)
    near_groups: list[dict[str, object]] = []
    near_keys: list[str] = []
    maxima: list[float] = []
    related_count = 0
    for key, signature in test_keys:
        full = _tokens(signature)
        probe = full - common
        candidates: set[int] = set()
        rare = sorted(probe, key=lambda token: document_frequency[token])[:4]
        for token in rare:
            candidates.update(index.get(token, ()))
        best = 0.0
        best_key = None
        for position in candidates:
            other_key, other = train_sets[position]
            if other_key == key:
                raise RuntimeError("template group leaked across the split")
            union = len(full | other)
            score = (len(full & other) / union) if union else 0.0
            if score > best:
                best = score
                best_key = other_key
        maxima.append(best)
        if best >= related:
            related_count += 1
        if best >= near:
            near_keys.append(key)
            if len(near_groups) < 8:
                near_groups.append(
                    {
                        "test_group": key[:180],
                        "train_group": None if best_key is None else best_key[:180],
                        "jaccard": best,
                    }
                )
    maxima_array = np.asarray(maxima, dtype=np.float64) if maxima else np.asarray([0.0])
    return {
        "train_groups": len(train_sets),
        "test_groups": len(test_keys),
        "exact_group_overlap": 0,
        "jaccard_at_least_0_8": len(near_groups),
        "jaccard_at_least_0_5": related_count,
        "median_max_jaccard": float(np.median(maxima_array)),
        "p95_max_jaccard": float(np.quantile(maxima_array, 0.95)),
        "examples": near_groups,
        "near_keys": near_keys,
        "method": (
            "Token Jaccard between each test template and train templates that share a rare token. "
            "Tokens present in more than 2% of train templates are ignored as candidates. "
            "A score of 0.8 or more is treated as a near-duplicate."
        ),
    }


def select_f1_threshold(labels: list[str], scores: np.ndarray) -> dict[str, object]:
    """Choose the anomaly threshold on validation labels only."""
    y = np.asarray([1 if label == "anomaly" else 0 for label in labels])
    values = np.asarray(scores, dtype=np.float64)
    if len(y) == 0 or len(np.unique(y)) < 2:
        return {
            "source": "default_because_validation_has_one_class",
            "value": None,
            "validation_f1": None,
            "validation_precision": None,
            "validation_recall": None,
        }
    candidates = np.unique(np.quantile(values, np.linspace(0.0, 1.0, 201)))
    best_f1 = -1.0
    best_precision = -1.0
    best_threshold = float(candidates[0])
    best_recall = 0.0
    for threshold in candidates:
        f1, precision, recall = _binary_f1(y, values >= threshold)
        if (f1, precision, float(threshold)) > (best_f1, best_precision, best_threshold):
            best_f1 = f1
            best_precision = precision
            best_recall = recall
            best_threshold = float(threshold)
    return {
        "source": "validation_max_anomaly_f1",
        "value": best_threshold,
        "validation_f1": best_f1,
        "validation_precision": best_precision,
        "validation_recall": best_recall,
        "tie_break": "Higher anomaly F1, then higher precision, then a higher threshold.",
    }


def _binary_f1(y: np.ndarray, predicted: np.ndarray) -> tuple[float, float, float]:
    tp = int(np.sum((y == 1) & predicted))
    fp = int(np.sum((y == 0) & predicted))
    fn = int(np.sum((y == 1) & ~predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return f1, precision, recall


def false_positives_per_thousand(matrix: list[list[int]], labels: list[str]) -> float | None:
    """False alarms per 1,000 actual normal rows. `matrix` rows follow `labels`."""
    if "normal" not in labels:
        return None
    normal_index = labels.index("normal")
    normal_row = matrix[normal_index]
    normal_total = sum(normal_row)
    if normal_total == 0:
        return None
    false_positives = sum(value for index, value in enumerate(normal_row) if index != normal_index)
    return 1000.0 * false_positives / normal_total


def calibration_report(
    labels: list[str], probabilities: np.ndarray, bins: int = 10
) -> dict[str, object]:
    """Expected calibration error of P(anomaly). This is not computed for raw anomaly scores."""
    y = np.asarray([1 if label == "anomaly" else 0 for label in labels], dtype=np.float64)
    probs = np.clip(np.asarray(probabilities, dtype=np.float64), 0.0, 1.0)
    if len(y) == 0 or len(np.unique(y)) < 2:
        return {
            "ece": None,
            "brier": None,
            "bins": [],
            "note": "Calibration is undefined because the scored rows contain one class.",
        }
    brier = float(np.mean((probs - y) ** 2))
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows = []
    ece = 0.0
    for start, end in zip(edges[:-1], edges[1:], strict=True):
        if end == 1.0:
            mask = (probs >= start) & (probs <= end)
        else:
            mask = (probs >= start) & (probs < end)
        count = int(np.sum(mask))
        if count == 0:
            continue
        confidence = float(np.mean(probs[mask]))
        observed = float(np.mean(y[mask]))
        ece += (count / len(y)) * abs(observed - confidence)
        rows.append(
            {
                "lower": float(start),
                "upper": float(end),
                "count": count,
                "mean_predicted": confidence,
                "observed_frequency": observed,
            }
        )
    return {"ece": ece, "brier": brier, "bins": rows, "note": "Equal-width bins of P(anomaly)."}


def counts_payload(normal: int, anomaly: int) -> dict[str, object]:
    return {
        "normal": normal,
        "anomaly": anomaly,
        "rows": normal + anomaly,
        "prevalence": prevalence(normal, anomaly),
    }
