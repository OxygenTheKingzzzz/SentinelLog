"""Dataset-specific parsers. Formats are not interchangeable.

Labels stay in the dataset's own unit: a BGL line, an HDFS block, an OpenStack
instance, or a Hadoop application. The alert token is removed before features
are built so it cannot leak into the model.
"""

import csv
import hashlib
import random
import re
import zipfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from sentinellog.risk.constants import PER_GROUP_CAP, SAMPLE_CAP
from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import group_key, keyword_severity, level_rank, normalize_template

_BGL_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})-(\d{2})\.(\d{2})\.(\d{2})\.(\d+)$")
_OS_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")
_OS_INSTANCE = re.compile(
    r"\[instance:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]"
    r"|servers/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_OS_LEVEL = re.compile(r"\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(\S+)")
_HADOOP_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_UUID_LINE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_ras_line(line: str, number: int, dataset: str) -> Example | None:
    """Parse one BGL or Thunderbird line. The first token is the label, not a feature."""
    parts = line.split(None, 9)
    if len(parts) < 10:
        return None
    label_token, _unix, _date, _node, detailed, _node2, _facility, component, level, message = parts
    native = "normal" if label_token == "-" else "anomaly"
    content = f"{component} {level} {message}".strip()
    moment = _ras_timestamp(detailed)
    return Example(
        key=f"{dataset}:{number}",
        content=content,
        group_key=group_key(content),
        timestamp=moment,
        component=component,
        pid=None,
        severity_rank=max(level_rank(level), keyword_severity(message)),
        label=native,
    )


def _ras_timestamp(text: str) -> datetime | None:
    match = _BGL_TIME.match(text)
    if match is None:
        return None
    year, month, day, hour, minute, second, micro = match.groups()
    return datetime(
        int(year),
        int(month),
        int(day),
        int(hour),
        int(minute),
        int(second),
        int(micro[:6].ljust(6, "0")),
        tzinfo=UTC,
    )


def _choose_groups(
    counts: dict[str, tuple[int, int]],
    *,
    global_cap: int,
    per_group: int,
    seed: int,
) -> dict[str, int]:
    by_class: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for key, (normal, anomaly) in counts.items():
        label = "anomaly" if anomaly > 0 and anomaly >= normal else "normal"
        by_class[label].append((key, normal + anomaly))
    rng = random.Random(seed)
    for label in by_class:
        by_class[label].sort()
        rng.shuffle(by_class[label])
    chosen: dict[str, int] = {}
    total = 0
    indexes = {label: 0 for label in by_class}
    labels = sorted(by_class)
    while total < global_cap and any(indexes[label] < len(by_class[label]) for label in labels):
        progressed = False
        for label in labels:
            index = indexes[label]
            if index >= len(by_class[label]):
                continue
            key, size = by_class[label][index]
            indexes[label] = index + 1
            take = min(per_group, size, global_cap - total)
            if take <= 0:
                return chosen
            chosen[key] = take
            total += take
            progressed = True
        if not progressed:
            break
    return chosen


def _reservoir_add(
    bucket: list[Example], seen: int, item: Example, cap: int, rng: random.Random
) -> None:
    if len(bucket) < cap:
        bucket.append(item)
        return
    pick = rng.randrange(seen)
    if pick < cap:
        bucket[pick] = item


def sample_ras_lines(
    lines,
    *,
    dataset: str,
    seed: int,
    global_cap: int = SAMPLE_CAP,
    per_group: int = PER_GROUP_CAP,
) -> tuple[list[Example], dict[str, int]]:
    """Two-pass group sample. The label token is parsed out before the group key exists."""
    counts: dict[str, tuple[int, int]] = {}
    population = {"lines": 0, "parsed": 0, "normal": 0, "anomaly": 0, "skipped": 0}
    cached: list[str] | None
    if isinstance(lines, list):
        cached = lines
        iterator = cached
    else:
        cached = []
        iterator = lines
    for number, line in enumerate(iterator, start=1):
        if cached is not None and iterator is not cached:
            cached.append(line)
        population["lines"] += 1
        parsed = parse_ras_line(line, number, dataset)
        if parsed is None or parsed.label is None:
            population["skipped"] += 1
            continue
        population["parsed"] += 1
        population[parsed.label] += 1
        normal, anomaly = counts.get(parsed.group_key, (0, 0))
        if parsed.label == "anomaly":
            anomaly += 1
        else:
            normal += 1
        counts[parsed.group_key] = (normal, anomaly)
    chosen = _choose_groups(counts, global_cap=global_cap, per_group=per_group, seed=seed)
    rng = random.Random(seed)
    kept: dict[str, list[Example]] = {key: [] for key in chosen}
    seen: dict[str, int] = defaultdict(int)
    source = cached if cached is not None else lines
    for number, line in enumerate(source, start=1):
        parsed = parse_ras_line(line, number, dataset)
        if parsed is None or parsed.group_key not in chosen:
            continue
        seen[parsed.group_key] += 1
        _reservoir_add(
            kept[parsed.group_key], seen[parsed.group_key], parsed, chosen[parsed.group_key], rng
        )
    examples = [item for key in sorted(kept) for item in kept[key]]
    population["sampled"] = len(examples)
    population["template_groups"] = len(counts)
    population["sampled_groups"] = len(chosen)
    return examples, population


def iter_bgl_zip(path: Path):
    with zipfile.ZipFile(path) as archive:
        with archive.open("BGL.log") as handle:
            for raw in handle:
                yield raw.decode("utf-8", "replace").rstrip("\r\n")


def load_bgl_zip(path: Path, *, seed: int = 42) -> tuple[list[Example], dict[str, object]]:
    # The zip stream can be read twice; cache only if the caller passes a list.
    # Full BGL is hundreds of megabytes, so the first pass records group counts
    # and the second pass keeps a capped reservoir.
    counts: dict[str, tuple[int, int]] = {}
    population = {"lines": 0, "parsed": 0, "normal": 0, "anomaly": 0, "skipped": 0}
    for number, line in enumerate(iter_bgl_zip(path), start=1):
        population["lines"] += 1
        parsed = parse_ras_line(line, number, "bgl")
        if parsed is None or parsed.label is None:
            population["skipped"] += 1
            continue
        population["parsed"] += 1
        population[parsed.label] += 1
        normal, anomaly = counts.get(parsed.group_key, (0, 0))
        if parsed.label == "anomaly":
            counts[parsed.group_key] = (normal, anomaly + 1)
        else:
            counts[parsed.group_key] = (normal + 1, anomaly)
    chosen = _choose_groups(counts, global_cap=SAMPLE_CAP, per_group=PER_GROUP_CAP, seed=seed)
    rng = random.Random(seed)
    kept: dict[str, list[Example]] = {key: [] for key in chosen}
    seen: dict[str, int] = defaultdict(int)
    for number, line in enumerate(iter_bgl_zip(path), start=1):
        parsed = parse_ras_line(line, number, "bgl")
        if parsed is None or parsed.group_key not in chosen:
            continue
        seen[parsed.group_key] += 1
        _reservoir_add(
            kept[parsed.group_key],
            seen[parsed.group_key],
            parsed,
            chosen[parsed.group_key],
            rng,
        )
    examples = [item for key in sorted(kept) for item in kept[key]]
    meta = {
        "dataset": "bgl",
        "dataset_version": "loghub-zenodo-8196385-BGL.zip",
        "source_url": "https://zenodo.org/records/8196385/files/BGL.zip?download=1",
        "file_sha256": file_sha256(path),
        "label_unit": "line",
        "label_provenance": "dataset_native",
        "label_definition": (
            "The first whitespace-separated token is the published BGL alert label. "
            "'-' is normal and any other token is an alert. That token is removed "
            "before the template group and the model features are built."
        ),
        "population": {
            **population,
            "sampled": len(examples),
            "template_groups": len(counts),
            "sampled_groups": len(chosen),
        },
        "sample": {
            "seed": seed,
            "global_cap": SAMPLE_CAP,
            "per_group_cap": PER_GROUP_CAP,
            "method": (
                "Whole template groups were drawn with a seeded class round-robin "
                "before the train/test split. Each group contributes at most "
                f"{PER_GROUP_CAP} lines."
            ),
        },
    }
    return examples, meta


def load_ras_file(
    path: Path, dataset: str, *, seed: int = 42
) -> tuple[list[Example], dict[str, object]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    examples, population = sample_ras_lines(lines, dataset=dataset, seed=seed)
    return examples, {
        "dataset": dataset,
        "dataset_version": path.name,
        "source_url": None,
        "file_sha256": file_sha256(path),
        "label_unit": "line",
        "label_provenance": "dataset_native",
        "label_definition": (
            "The first token is the published alert label. '-' is normal. "
            "The token is not used as a feature."
        ),
        "population": population,
        "sample": {"seed": seed, "global_cap": SAMPLE_CAP, "per_group_cap": PER_GROUP_CAP},
    }


def load_hdfs(
    label_csv: Path, traces_csv: Path, *, seed: int = 42
) -> tuple[list[Example], dict[str, object]]:
    """Join Loghub HDFS block labels to event-template traces.

    The Success/Fail column inside the trace file is ignored. The verified label
    is anomaly_label.csv. One example is one block.
    """
    labels: dict[str, str] = {}
    with label_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            native = row["Label"].strip().lower()
            if native not in {"normal", "anomaly"}:
                continue
            labels[row["BlockId"]] = native
    counts: dict[str, tuple[int, int]] = {}
    population = {
        "labeled_blocks": len(labels),
        "normal": sum(1 for value in labels.values() if value == "normal"),
        "anomaly": sum(1 for value in labels.values() if value == "anomaly"),
        "traces": 0,
        "joined": 0,
    }
    csv.field_size_limit(10_000_000)

    def blocks():
        with traces_csv.open(newline="", encoding="utf-8") as handle:
            yield from csv.DictReader(handle)

    for row in blocks():
        population["traces"] += 1
        block = row["BlockId"]
        native = labels.get(block)
        if native is None:
            continue
        population["joined"] += 1
        content = _hdfs_content(row.get("Features", ""))
        key = group_key(content)
        normal, anomaly = counts.get(key, (0, 0))
        if native == "anomaly":
            counts[key] = (normal, anomaly + 1)
        else:
            counts[key] = (normal + 1, anomaly)
    chosen = _choose_groups(counts, global_cap=SAMPLE_CAP, per_group=PER_GROUP_CAP, seed=seed)
    rng = random.Random(seed)
    kept: dict[str, list[Example]] = {key: [] for key in chosen}
    seen: dict[str, int] = defaultdict(int)
    for row in blocks():
        block = row["BlockId"]
        native = labels.get(block)
        if native is None:
            continue
        content = _hdfs_content(row.get("Features", ""))
        key = group_key(content)
        if key not in chosen:
            continue
        seen[key] += 1
        example = Example(
            key=block,
            content=content,
            group_key=key,
            timestamp=None,
            component="hdfs.block",
            pid=None,
            severity_rank=0,
            label=native,
        )
        _reservoir_add(kept[key], seen[key], example, chosen[key], rng)
    examples = [item for key in sorted(kept) for item in kept[key]]
    population["sampled"] = len(examples)
    population["template_groups"] = len(counts)
    population["sampled_groups"] = len(chosen)
    meta = {
        "dataset": "hdfs",
        "dataset_version": "loghub-zenodo-8196385-HDFS_v1",
        "source_url": "https://zenodo.org/records/8196385/files/HDFS_v1.zip?download=1",
        "file_sha256": file_sha256(label_csv),
        "traces_sha256": file_sha256(traces_csv),
        "label_unit": "block",
        "label_provenance": "dataset_native",
        "label_definition": (
            "anomaly_label.csv BlockId label. Normal and Anomaly are the verified "
            "binary classes. Event_traces Features is the template sequence. "
            "The trace file's Success/Fail column and Latency are not features and not labels."
        ),
        "population": population,
        "sample": {
            "seed": seed,
            "global_cap": SAMPLE_CAP,
            "per_group_cap": PER_GROUP_CAP,
            "method": (
                "Seeded class round-robin over block template groups before the train/test split."
            ),
        },
    }
    return examples, meta


def _hdfs_content(features: str) -> str:
    text = features.strip().strip("[]")
    return " ".join(part.strip() for part in text.split(",") if part.strip())


def load_openstack(directory: Path) -> tuple[list[Example], dict[str, object]]:
    """One example per VM instance. The label file names four anomalous instance ids."""
    label_path = directory / "anomaly_labels.txt"
    anomalous = {
        line.strip()
        for line in label_path.read_text(encoding="utf-8").splitlines()
        if _UUID_LINE.match(line.strip())
    }
    files = [
        directory / "openstack_normal1.log",
        directory / "openstack_normal2.log",
        directory / "openstack_abnormal.log",
    ]
    buckets: dict[str, list[str]] = defaultdict(list)
    first_time: dict[str, datetime] = {}
    for path in files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            ids = [left or right for left, right in _OS_INSTANCE.findall(line)]
            if not ids:
                continue
            moment = _openstack_time(line)
            cleaned = normalize_template(line)
            for instance_id in ids:
                if len(buckets[instance_id]) < 40:
                    buckets[instance_id].append(cleaned)
                if moment is not None and instance_id not in first_time:
                    first_time[instance_id] = moment
    examples: list[Example] = []
    for instance_id in sorted(buckets):
        content = " ".join(buckets[instance_id])
        level = _OS_LEVEL.search(content)
        component = level.group(2) if level else "openstack"
        examples.append(
            Example(
                key=instance_id,
                content=content,
                group_key=group_key(content),
                timestamp=first_time.get(instance_id),
                component=component,
                pid=None,
                severity_rank=keyword_severity(content),
                label="anomaly" if instance_id in anomalous else "normal",
            )
        )
    meta = {
        "dataset": "openstack",
        "dataset_version": "loghub-zenodo-8196385-OpenStack.tar.gz",
        "source_url": "https://zenodo.org/records/8196385/files/OpenStack.tar.gz?download=1",
        "file_sha256": file_sha256(label_path),
        "label_unit": "vm_instance",
        "label_provenance": "dataset_native",
        "label_definition": (
            "anomaly_labels.txt lists VM instance ids with injected anomalies. "
            "Every other instance id found in [instance: ...] or /servers/<id> is normal. "
            "Lines that mention no instance are unlabeled and are excluded. "
            "Instance ids are replaced before grouping so the model cannot memorize the four ids."
        ),
        "population": {
            "instances": len(examples),
            "anomaly": sum(1 for item in examples if item.label == "anomaly"),
            "normal": sum(1 for item in examples if item.label == "normal"),
            "anomalous_ids_in_label_file": len(anomalous),
            "template_groups": len({item.group_key for item in examples}),
        },
        "sample": {"seed": None, "method": "Every discovered instance is kept. No subsample."},
    }
    return examples, meta


def parse_hadoop_labels(text: str) -> dict[str, str]:
    """Map application id to normal or anomaly. Failure types stay binary anomalies."""
    labels: dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("The logs"):
            continue
        if line.startswith("###"):
            section = ""
            continue
        if line.endswith(":") and not line.startswith("+"):
            section = line[:-1].strip().lower()
            continue
        if line.startswith("+"):
            app = line[1:].strip()
            labels[app] = "normal" if section == "normal" else "anomaly"
    return labels


def load_hadoop(path: Path) -> tuple[list[Example], dict[str, object]]:
    """One example per labeled application. Container lines from one app stay together."""
    with zipfile.ZipFile(path) as archive:
        label_text = archive.read("abnormal_label.txt").decode("utf-8")
        labels = parse_hadoop_labels(label_text)
        lines: dict[str, list[str]] = defaultdict(list)
        moments: dict[str, datetime] = {}
        for info in archive.infolist():
            parts = info.filename.split("/")
            if len(parts) < 2 or not parts[0].startswith("application_"):
                continue
            app = parts[0]
            if app not in labels or info.is_dir() or not info.filename.endswith(".log"):
                continue
            with archive.open(info) as handle:
                for raw in handle:
                    if len(lines[app]) >= 80:
                        break
                    text = raw.decode("utf-8", "replace").strip()
                    if not text:
                        continue
                    lines[app].append(normalize_template(text))
                    if app not in moments:
                        match = _HADOOP_TIME.match(text)
                        if match:
                            moments[app] = datetime.strptime(
                                match.group(1), "%Y-%m-%d %H:%M:%S"
                            ).replace(tzinfo=UTC)
    examples = []
    for app in sorted(labels):
        content = " ".join(lines.get(app, []))
        if not content:
            continue
        examples.append(
            Example(
                key=app,
                content=content,
                group_key=group_key(content),
                timestamp=moments.get(app),
                component="hadoop.application",
                pid=None,
                severity_rank=keyword_severity(content),
                label=labels[app],
            )
        )
    meta = {
        "dataset": "hadoop",
        "dataset_version": "loghub-zenodo-8196385-Hadoop.zip",
        "source_url": "https://zenodo.org/records/8196385/files/Hadoop.zip?download=1",
        "file_sha256": file_sha256(path),
        "label_unit": "application",
        "label_provenance": "dataset_native",
        "label_definition": (
            "abnormal_label.txt marks each application Normal or a failure type "
            "(machine down, network disconnection, disk full). Failure types are "
            "binary anomalies. They are not LOW/MEDIUM/HIGH/CRITICAL labels. "
            "Applications absent from the label file are excluded."
        ),
        "population": {
            "labeled_applications": len(labels),
            "examples": len(examples),
            "normal": sum(1 for item in examples if item.label == "normal"),
            "anomaly": sum(1 for item in examples if item.label == "anomaly"),
            "template_groups": len({item.group_key for item in examples}),
        },
        "sample": {
            "method": "Up to 80 normalized lines from each labeled application's containers.",
        },
    }
    return examples, meta


def _openstack_time(line: str) -> datetime | None:
    match = _OS_TIME.search(line)
    if match is None:
        return None
    return datetime.strptime(
        f"{match.group(1)} {match.group(2)}",
        "%Y-%m-%d %H:%M:%S",
    ).replace(tzinfo=UTC)
