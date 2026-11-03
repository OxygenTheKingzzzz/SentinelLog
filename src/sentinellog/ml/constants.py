"""Fixed anomaly-detection settings. None of these are fit to labels."""

WINDOW_SECONDS = 3600
WINDOW_TYPE = "tumbling"
TRAIN_FRACTION = 0.7
MIN_SPLIT = 5
BASELINE_Z_THRESHOLD = 3.5
# Flag when isolation_score > this. 0 matches sklearn's contamination offset
# (decision_function < 0). It is not tuned on labels.
ISOLATION_SCORE_THRESHOLD = 0.0
CONTAMINATION = 0.05
RANDOM_STATE = 42
N_ESTIMATORS = 100
Z_CAP = 10.0
Z_CONSISTENCY = 0.6745
TOP_CONTRIBUTIONS = 5
MAX_BASELINE_FEATURES = 8
ALGORITHM = "isolation_forest+robust_z"

# root is the only uid-0 login principal in Linux_2k. This constant is local
# to the feature pipeline. It is not read from security_alerts.
PRIVILEGED_USERNAMES = frozenset({"root"})
AUTH_FAILURE_EVENT_IDS = frozenset({"E16", "E17", "E18", "E19"})
FTP_CONNECTION_EVENT_ID = "E29"
SERVICE_ERROR_EVENT_ID = "E8"

NO_GROUND_TRUTH = (
    "Linux_2k has no malicious or benign labels. "
    "Precision, recall, F1, and ROC-AUC are not computed. "
    "Scores are experimental anomaly rankings, not confirmed compromise."
)

SCALAR_FEATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("event_count", ("event_timestamp",)),
    ("failed_auth_count", ("component", "event_id", "content")),
    ("distinct_source_hosts", ("source_ip", "content")),
    ("distinct_usernames", ("username",)),
    ("distinct_templates", ("event_id",)),
    ("template_entropy", ("event_id",)),
    ("max_template_count", ("event_id",)),
    ("distinct_components", ("component",)),
    ("component_entropy", ("component",)),
    ("privileged_attempt_count", ("username", "component", "event_id", "content")),
    ("ftp_connection_count", ("event_id",)),
    ("service_error_count", ("event_id", "component", "content")),
)
