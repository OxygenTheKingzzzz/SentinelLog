"""Group splits. Lines that share a normalized template stay on one side."""

from collections import defaultdict
from dataclasses import dataclass

import numpy as np
from sklearn.model_selection import train_test_split

from sentinellog.risk.constants import TEST_FRACTION
from sentinellog.risk.records import Example


@dataclass(frozen=True)
class GroupSplit:
    train: list[Example]
    test: list[Example]
    protocol: str
    note: str

    @property
    def train_groups(self) -> set[str]:
        return {item.group_key for item in self.train}

    @property
    def test_groups(self) -> set[str]:
        return {item.group_key for item in self.test}


def group_examples(examples: list[Example]) -> dict[str, list[Example]]:
    grouped: dict[str, list[Example]] = defaultdict(list)
    for item in examples:
        grouped[item.group_key].append(item)
    return grouped


def majority_label(items: list[Example]) -> str:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        if item.label is not None:
            counts[item.label] += 1
    if not counts:
        return "unlabeled"
    # Ties break toward the higher severity name so the choice is stable.
    return max(counts.items(), key=lambda pair: (pair[1], pair[0]))[0]


def _materialize(
    grouped: dict[str, list[Example]],
    train_keys: list[str],
    test_keys: list[str],
    protocol: str,
    note: str,
) -> GroupSplit:
    overlap = set(train_keys) & set(test_keys)
    if overlap:
        raise RuntimeError("template group leaked across the split")
    train = [item for key in train_keys for item in grouped[key]]
    test = [item for key in test_keys for item in grouped[key]]
    return GroupSplit(train=train, test=test, protocol=protocol, note=note)


def split_groups(
    examples: list[Example],
    *,
    test_fraction: float = TEST_FRACTION,
    seed: int,
) -> GroupSplit:
    """Stratify by the majority label of each template group when every class has two groups."""
    grouped = group_examples(examples)
    keys = sorted(grouped)
    if len(keys) < 2:
        raise ValueError("need at least two template groups to separate train and test")
    labels = [majority_label(grouped[key]) for key in keys]
    counts: dict[str, int] = defaultdict(int)
    for label in labels:
        counts[label] += 1
    can_stratify = len(counts) >= 2 and all(value >= 2 for value in counts.values())
    if can_stratify:
        train_keys, test_keys = train_test_split(
            keys,
            test_size=test_fraction,
            random_state=seed,
            stratify=labels,
        )
        protocol = "stratified_group"
        note = (
            "Template groups were split with stratification on the majority label. "
            "No normalized template appears in both sides."
        )
    else:
        order = np.array(keys)
        rng = np.random.RandomState(seed)
        rng.shuffle(order)
        n_test = int(round(len(order) * test_fraction))
        n_test = min(max(n_test, 1), len(order) - 1)
        test_keys = order[:n_test].tolist()
        train_keys = order[n_test:].tolist()
        protocol = "group_holdout"
        note = (
            "A class has fewer than two template groups, so the split is a seeded "
            "group holdout and is not stratified."
        )
    return _materialize(grouped, list(train_keys), list(test_keys), protocol, note)


def holdout_positive_groups(
    examples: list[Example],
    *,
    positive: str,
    test_fraction: float = TEST_FRACTION,
    seed: int,
) -> GroupSplit:
    """Put every positive template group in test and split the remaining groups.

    Used when the positive class is a single template. Supervised training would
    otherwise have to train and test on copies of that same template.
    """
    grouped = group_examples(examples)
    positive_keys = []
    other_keys = []
    for key in sorted(grouped):
        if majority_label(grouped[key]) == positive:
            positive_keys.append(key)
        else:
            other_keys.append(key)
    if len(other_keys) < 2:
        raise ValueError("need at least two non-positive template groups")
    other_split = split_groups(
        [item for key in other_keys for item in grouped[key]],
        test_fraction=test_fraction,
        seed=seed,
    )
    train_keys = sorted(other_split.train_groups)
    test_keys = sorted(other_split.test_groups | set(positive_keys))
    note = (
        "Every positive template group was held out of training. "
        "Isolation Forest is fit only on the training groups. " + other_split.note
    )
    return _materialize(grouped, train_keys, test_keys, "positive_groups_held_out", note)


def positive_group_count(examples: list[Example], positive: str) -> int:
    grouped = group_examples(examples)
    return sum(1 for items in grouped.values() if majority_label(items) == positive)
