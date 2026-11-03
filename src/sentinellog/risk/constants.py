"""Fixed risk-classification settings. Thresholds are not fit to labels."""

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BINARY_LABELS = ("normal", "anomaly")
ALGORITHMS = ("isolation_forest", "random_forest", "tfidf_logreg")
VERIFIED_PROVENANCE = frozenset({"verified_manual", "verified_import", "dataset_native"})
WEAK_PROVENANCE = "weak_rule"

NOT_EVALUATED = "Not evaluated — ground-truth labels required"

RANDOM_SEED = 42
TEST_FRACTION = 0.30
CV_FOLDS = 3
# Caps apply after the group split, independently to each side.
TRAIN_CAP = 20_000
TEST_CAP = 8_000
CV_CAP = 6_000
PER_GROUP_CAP = 40
SAMPLE_CAP = 28_000

ISOLATION_CONTAMINATION = 0.05
ISOLATION_ESTIMATORS = 100
FOREST_ESTIMATORS = 80
# Train-score quantiles. These are a display policy for unsupervised bands.
BAND_QUANTILES = (0.90, 0.97, 0.995)

SEVERITY_TO_RISK = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}
RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
BINARY_TO_RISK = {"normal": "LOW", "anomaly": "HIGH"}
