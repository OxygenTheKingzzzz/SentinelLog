"""Run held-out evaluations for datasets that publish real labels.

The JSON this module writes is the only place dashboard metrics come from.
Linux stays `not_evaluated` because Loghub does not label it.
"""

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinellog.risk.compare import ModelRun, compare_models
from sentinellog.risk.constants import NOT_EVALUATED, RANDOM_SEED
from sentinellog.risk.datasets import (
    load_bgl_zip,
    load_hadoop,
    load_hdfs,
    load_openstack,
    load_ras_file,
)
from sentinellog.risk.records import Example

LINUX_DETAIL = (
    "Loghub Linux has no malicious or benign labels and no LOW/MEDIUM/HIGH/CRITICAL "
    "ground truth. Isolation Forest can still assign score bands. Those bands are "
    "not verified risk labels."
)


def run_labeled(
    examples: list[Example], meta: dict[str, Any], *, seed: int = RANDOM_SEED
) -> dict[str, Any]:
    counts = Counter(item.label for item in examples)
    experiment = {
        "dataset": meta["dataset"],
        "dataset_version": meta["dataset_version"],
        "source_url": meta.get("source_url"),
        "file_sha256": meta.get("file_sha256"),
        "label_unit": meta["label_unit"],
        "label_provenance": meta["label_provenance"],
        "label_definition": meta["label_definition"],
        "population": meta["population"],
        "sample": meta["sample"],
        "task": "binary_anomaly",
        "random_seed": seed,
        "test_fraction": 0.3,
        "models": [],
    }
    if len(examples) < 8 or len(counts) < 2:
        experiment["models"] = [
            _unevaluated(
                algorithm,
                "The labeled sample does not contain both classes, so accuracy is not computed.",
            )
            for algorithm in ("isolation_forest", "random_forest", "tfidf_logreg")
        ]
        return experiment
    runs = compare_models(examples, task="binary_anomaly", seed=seed)
    experiment["models"] = [_model_payload(run) for run in runs]
    return experiment


def _unevaluated(algorithm: str, detail: str) -> dict[str, Any]:
    return {
        "algorithm": algorithm,
        "task": "binary_anomaly",
        "fit_protocol": "not_fit",
        "n_train": 0,
        "n_test": 0,
        "metrics_status": "not_evaluated",
        "metrics_note": NOT_EVALUATED,
        "detail": detail,
        "metrics": None,
        "cv": {"folds": 0, "scope": "training groups only", "note": detail},
        "real_world": False,
    }


def _model_payload(run: ModelRun) -> dict[str, Any]:
    return {
        "algorithm": run.algorithm,
        "task": run.task,
        "fit_protocol": run.fit_protocol,
        "n_train": run.n_train,
        "n_test": run.n_test,
        "metrics_status": run.metrics_status,
        "metrics_note": run.metrics_note,
        "detail": run.detail,
        "metrics": run.metrics,
        "cv": {key: value for key, value in run.cv.items() if key != "bundle"},
        "real_world": run.metrics_status == "evaluated" and run.metrics is not None,
    }


def linux_experiment() -> dict[str, Any]:
    return {
        "dataset": "linux",
        "dataset_version": "loghub-Linux_2k",
        "source_url": "https://github.com/logpai/loghub/tree/master/Linux",
        "file_sha256": None,
        "label_unit": "line",
        "label_provenance": "none",
        "label_definition": "Loghub's dataset table leaves Linux unlabeled.",
        "population": {"lines": 2000, "verified_risk_labels": 0},
        "sample": {"method": "No labeled split. The bundled Linux_2k file has no risk labels."},
        "task": "multiclass_risk",
        "random_seed": RANDOM_SEED,
        "test_fraction": None,
        "models": [
            {
                "algorithm": "isolation_forest",
                "task": "unsupervised_band",
                "fit_protocol": "group_holdout",
                "n_train": None,
                "n_test": None,
                "metrics_status": "not_evaluated",
                "metrics_note": NOT_EVALUATED,
                "detail": LINUX_DETAIL,
                "metrics": None,
                "cv": {"folds": 0, "scope": "training groups only", "note": LINUX_DETAIL},
                "real_world": False,
            }
        ],
    }


def _extract_hdfs(root: Path) -> tuple[Path, Path] | None:
    label = root / "hdfs-preprocessed" / "preprocessed" / "anomaly_label.csv"
    traces = root / "hdfs-preprocessed" / "preprocessed" / "Event_traces.csv"
    if label.is_file() and traces.is_file():
        return label, traces
    archive = root / "HDFS_v1.zip"
    if not archive.is_file():
        return None
    import zipfile

    destination = root / "hdfs-preprocessed"
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zipped:
        zipped.extract("preprocessed/anomaly_label.csv", destination)
        zipped.extract("preprocessed/Event_traces.csv", destination)
    return label, traces


def evaluate_directory(root: Path) -> dict[str, Any]:
    experiments: list[dict[str, Any]] = []
    bgl = root / "BGL.zip"
    if bgl.is_file():
        examples, meta = load_bgl_zip(bgl, seed=RANDOM_SEED)
        experiments.append(run_labeled(examples, meta))
    hdfs = _extract_hdfs(root)
    if hdfs is not None:
        examples, meta = load_hdfs(hdfs[0], hdfs[1], seed=RANDOM_SEED)
        experiments.append(run_labeled(examples, meta))
    if (root / "anomaly_labels.txt").is_file():
        examples, meta = load_openstack(root)
        experiments.append(run_labeled(examples, meta))
    hadoop = root / "Hadoop.zip"
    if hadoop.is_file():
        examples, meta = load_hadoop(hadoop)
        experiments.append(run_labeled(examples, meta))
    thunderbird = root / "Thunderbird_2k.log"
    if thunderbird.is_file():
        examples, meta = load_ras_file(thunderbird, "thunderbird", seed=RANDOM_SEED)
        meta["source_url"] = (
            "https://raw.githubusercontent.com/logpai/loghub/master/Thunderbird/Thunderbird_2k.log"
        )
        meta["dataset_version"] = "loghub-Thunderbird_2k"
        meta["label_definition"] = (
            "Thunderbird uses the same first-token alert label as BGL. "
            "The published 2k sample is not the full 211,212,192-line corpus."
        )
        experiments.append(run_labeled(examples, meta))
    experiments.append(linux_experiment())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "sentinellog.risk.experiments",
        "seed": RANDOM_SEED,
        "experiments": experiments,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sentinellog.risk.experiments")
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    payload = evaluate_directory(args.dataset_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    for experiment in payload["experiments"]:
        print(experiment["dataset"], [model["metrics_status"] for model in experiment["models"]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
