# Realistic prevalence and chronological evaluation

Generated 2026-11-03T11:47:44Z by `sentinellog.risk.realistic` with seed 42.

Template groups are assigned to train, validation, and test before sampling, feature fitting, or threshold selection. Row caps are uniform inside one side, so they keep that side's anomaly prevalence. The validation side chooses the threshold. The test side is scored once. Hyperparameters stay at the benchmark values.

The original file `published_results.json` is unchanged. Its BGL and HDFS numbers come from a class round-robin sample and are a rebalanced benchmark, not a realistic-prevalence result.

LOW, MEDIUM, HIGH, and CRITICAL on Linux are estimated score bands. Binary accuracy does not validate those four levels. Linux_2k stays unevaluated.

## How each split was built

Train, validation, and test each receive whole template groups. About 60% of groups go to train, 20% to validation, and 20% to test. A uniform reservoir then caps each side at 20,000 train rows, 8,000 validation rows, and 20,000 test rows. The cap does not rebalance classes. Feature vocabularies and the Isolation Forest are fit on train. The anomaly threshold maximizes anomaly F1 on validation, with ties broken toward higher precision and then a higher threshold. Test labels are used once, for the reported metrics.

The chronological protocol orders templates by their earliest timestamp. It is omitted when timestamps are missing. A template that begins in the training window is never copied into the future test, even if that template continues to emit lines later. Those later lines remain in train. The report counts train templates whose span crosses the test boundary.

Near-duplicates are token-Jaccard matches of at least 0.8 between a test template and a train template. Metrics with those test templates removed use the same fitted model and the same validation threshold.

## bgl

Unit: line. The first whitespace-separated token is the published BGL alert label. '-' is normal. That token is removed before the template and the features.
Population prevalence 0.074 (348460 anomaly / 4365033 normal, 47160 template groups).
Anomalous template groups: 2285. Groups that contain both labels: 1.
Features available: component, level word, and message text; severity rank from the level word and keywords; hour sine and cosine; template and component rarity fit on the training rows only.
Features excluded: alert token; node name; raw unix timestamp; line number.
Alert-token copies inside the message body: 0. Raw identifiers found inside features: 0.
Severity rank 0: anomaly prevalence 0.000 (0 anomaly / 3359257 normal).
Severity rank 1: anomaly prevalence 0.000 (0 anomaly / 23322 normal).
Severity rank 2: anomaly prevalence 0.000 (0 anomaly / 309002 normal).
Severity rank 3: anomaly prevalence 0.341 (348460 anomaly / 673452 normal).

### realistic_group

Template groups were assigned with stratification on the majority label before any sampling. Each group is in train, validation, or test only.
Full split before the row cap: train prevalence 0.094 (281213 / 2987449 rows); validation prevalence 0.032 (14898 / 471710 rows); test prevalence 0.042 (52349 / 1254334 rows); population prevalence 0.074 (348460 / 4713493 rows).
Evaluated rows: train 20000 prevalence 0.094; validation 8000 prevalence 0.027; test 20000 prevalence 0.040.
Template groups that contain any anomaly: 2285. Their split placement: {'validation': 457, 'train': 1371, 'test': 457}.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 9432. Jaccard >= 0.5: 6640. Median nearest-train Jaccard 0.714.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | evaluated | 0.951 | 0.219 | 0.084 | 0.122 | 0.705 | 0.139 | 12.660 | 0.007 |
| random_forest | evaluated | 0.982 | 0.998 | 0.546 | 0.706 | 0.943 | 0.642 | 0.052 | 0.338 |
| tfidf_logreg | evaluated | 0.978 | 1.000 | 0.455 | 0.626 | 0.999 | 0.983 | 0.000 | 0.925 |
| severity_rank_only | evaluated | 0.830 | 0.192 | 1.000 | 0.321 | 0.911 | 0.192 | 177.243 | 0.875 |

isolation_forest confusion matrix ['normal', 'anomaly']: [[18951, 243], [738, 68]].
isolation_forest calibration ECE 0.017, Brier 0.038. Platt scaling was fit on validation scores only. The raw Isolation Forest score is not a class probability.
isolation_forest after removing near-duplicates: F1 0.235, precision 0.944, n=15635.
isolation_forest at the default threshold 0.0: F1 0.126, FP/1,000 16.828.
random_forest confusion matrix ['normal', 'anomaly']: [[19193, 1], [366, 440]].
random_forest calibration ECE 0.008, Brier 0.018. Reliability of P(anomaly) on the test rows. The threshold was not used.
random_forest after removing near-duplicates: F1 0.433, precision 1.000, n=15635.
random_forest at the default threshold 0.5: F1 0.630, FP/1,000 0.000.
tfidf_logreg confusion matrix ['normal', 'anomaly']: [[19194, 0], [439, 367]].
tfidf_logreg calibration ECE 0.032, Brier 0.010. Reliability of P(anomaly) on the test rows. The threshold was not used.
tfidf_logreg after removing near-duplicates: F1 0.291, precision 1.000, n=15635.
tfidf_logreg at the default threshold 0.5: F1 0.700, FP/1,000 0.000.

### chronological_group

Each template is assigned by its earliest timestamp. Train is the earliest groups, validation the next block, and test the latest groups. A template that starts during training never appears in the test.
Full split before the row cap: train prevalence 0.076 (282018 / 3714545 rows); validation prevalence 0.100 (29472 / 294727 rows); test prevalence 0.052 (36970 / 704221 rows); population prevalence 0.074 (348460 / 4713493 rows).
Evaluated rows: train 20000 prevalence 0.077; validation 8000 prevalence 0.103; test 20000 prevalence 0.053.
Template groups that contain any anomaly: 2285. Their split placement: {'train': 690, 'validation': 1506, 'test': 89}.
Train templates whose time span crosses the test boundary: 1486.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 9432. Jaccard >= 0.5: 1340. Median nearest-train Jaccard 0.000.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | evaluated | 0.053 | 0.053 | 1.000 | 0.101 | 0.891 | 0.280 | 999.736 | -0.112 |
| random_forest | evaluated | 0.992 | 0.999 | 0.846 | 0.916 | 0.998 | 0.966 | 0.053 | 0.375 |
| tfidf_logreg | evaluated | 0.991 | 1.000 | 0.825 | 0.904 | 0.999 | 0.988 | 0.000 | 0.866 |
| severity_rank_only | evaluated | 0.756 | 0.179 | 1.000 | 0.304 | 0.871 | 0.179 | 257.605 | 0.889 |

isolation_forest confusion matrix ['normal', 'anomaly']: [[5, 18931], [0, 1064]].
isolation_forest calibration ECE 0.123, Brier 0.068. Platt scaling was fit on validation scores only. The raw Isolation Forest score is not a class probability.
isolation_forest after removing near-duplicates: F1 0.110, precision 0.058, n=18206.
isolation_forest at the default threshold 0.0: F1 0.501, FP/1,000 72.085.
random_forest confusion matrix ['normal', 'anomaly']: [[18935, 1], [164, 900]].
random_forest calibration ECE 0.019, Brier 0.008. Reliability of P(anomaly) on the test rows. The threshold was not used.
random_forest after removing near-duplicates: F1 0.916, precision 0.999, n=18206.
random_forest at the default threshold 0.5: F1 0.905, FP/1,000 0.000.
tfidf_logreg confusion matrix ['normal', 'anomaly']: [[18936, 0], [186, 878]].
tfidf_logreg calibration ECE 0.026, Brier 0.008. Reliability of P(anomaly) on the test rows. The threshold was not used.
tfidf_logreg after removing near-duplicates: F1 0.905, precision 1.000, n=18206.
tfidf_logreg at the default threshold 0.5: F1 0.904, FP/1,000 0.106.

## hdfs

Unit: block. anomaly_label.csv supplies Normal or Anomaly for a block. Features are the event-id sequence. Success/Fail, latency, and BlockId are excluded.
Population prevalence 0.029 (16838 anomaly / 558223 normal, 18373 template groups).
Anomalous template groups: 4122. Groups that contain both labels: 10.
Features available: event-id sequence from Event_traces Features.
Features excluded: BlockId; Success/Fail; Type; TimeInterval; Latency.
Alert-token copies inside the message body: 0. Raw identifiers found inside features: 0.
Severity rank 0: anomaly prevalence 0.029 (16838 anomaly / 558223 normal).

### realistic_group

Template groups were assigned with stratification on the majority label before any sampling. Each group is in train, validation, or test only.
Full split before the row cap: train prevalence 0.023 (8296 / 367261 rows); validation prevalence 0.022 (3263 / 151719 rows); test prevalence 0.094 (5279 / 56081 rows); population prevalence 0.029 (16838 / 575061 rows).
Evaluated rows: train 20000 prevalence 0.022; validation 8000 prevalence 0.020; test 20000 prevalence 0.093.
Template groups that contain any anomaly: 4124. Their split placement: {'validation': 824, 'train': 2475, 'test': 825}.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 3675. Jaccard >= 0.5: 134. Median nearest-train Jaccard 0.000.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | evaluated | 0.671 | 0.165 | 0.622 | 0.261 | 0.643 | 0.204 | 323.465 | -0.025 |
| random_forest | evaluated | 0.994 | 0.951 | 0.987 | 0.969 | 0.998 | 0.986 | 5.182 | 0.325 |
| tfidf_logreg | evaluated | 0.995 | 0.948 | 0.999 | 0.973 | 0.996 | 0.938 | 5.624 | 0.577 |
| single_event_id | evaluated | 0.930 | 1.000 | 0.245 | 0.393 | 0.622 | 0.315 | 0.000 | — |

isolation_forest confusion matrix ['normal', 'anomaly']: [[12271, 5867], [704, 1158]].
isolation_forest calibration ECE 0.069, Brier 0.089. Platt scaling was fit on validation scores only. The raw Isolation Forest score is not a class probability.
isolation_forest after removing near-duplicates: F1 0.177, precision 0.106, n=19452.
isolation_forest at the default threshold 0.0: F1 0.275, FP/1,000 116.165.
random_forest confusion matrix ['normal', 'anomaly']: [[18044, 94], [24, 1838]].
random_forest calibration ECE 0.031, Brier 0.010. Reliability of P(anomaly) on the test rows. The threshold was not used.
random_forest after removing near-duplicates: F1 0.961, precision 0.933, n=19452.
random_forest at the default threshold 0.5: F1 0.977, FP/1,000 1.544.
tfidf_logreg confusion matrix ['normal', 'anomaly']: [[18036, 102], [2, 1860]].
tfidf_logreg calibration ECE 0.034, Brier 0.010. Reliability of P(anomaly) on the test rows. The threshold was not used.
tfidf_logreg after removing near-duplicates: F1 0.962, precision 0.928, n=19452.
tfidf_logreg at the default threshold 0.5: F1 0.973, FP/1,000 5.679.

### chronological_group

Not used. Fewer than 95% of parsed rows have a timestamp, so a time split would not be a future holdout.

## openstack

Unit: vm_instance. anomaly_labels.txt lists VM instance ids with injected anomalies. Every other instance id found in [instance: ...] or /servers/<id> is normal. Lines that mention no instance are unlabeled and are excluded. Instance ids are replaced before grouping so the model cannot memorize the four ids.
Population prevalence 0.002 (4 anomaly / 2065 normal, 39 template groups).
Anomalous template groups: 0. Groups that contain both labels: 1.
Features available: normalized log text for one instance or application.
Features excluded: raw instance or application id.
Alert-token copies inside the message body: 0. Raw identifiers found inside features: 0.
Each instance is one example. At most 40 normalized lines are kept per instance before the instance groups are split. Instance ids are replaced with <*>.

### realistic_group

A class has fewer than three template groups, so the split is a seeded group holdout and is not stratified. Supervised training is refused when the positive class has fewer than two independent groups.
Full split before the row cap: train prevalence 0.003 (4 / 1385 rows); validation prevalence 0.000 (0 / 570 rows); test prevalence 0.000 (0 / 114 rows); population prevalence 0.002 (4 / 2069 rows).
Evaluated rows: train 1385 prevalence 0.003; validation 570 prevalence 0.000; test 114 prevalence 0.000.
Template groups that contain any anomaly: 1. Their split placement: {'train': 1}.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 8. Jaccard >= 0.5: 8. Median nearest-train Jaccard 1.000.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| random_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| tfidf_logreg | Not evaluated — ground-truth labels required | | | | | | | | |

isolation_forest: The held-out test set contains one class, so accuracy is not reported.
isolation_forest after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
random_forest: Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one.
tfidf_logreg: Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one.

### chronological_group

Each template is assigned by its earliest timestamp. Train is the earliest groups, validation the next block, and test the latest groups. A template that starts during training never appears in the test.
Full split before the row cap: train prevalence 0.002 (4 / 1856 rows); validation prevalence 0.000 (0 / 203 rows); test prevalence 0.000 (0 / 10 rows); population prevalence 0.002 (4 / 2069 rows).
Evaluated rows: train 1856 prevalence 0.002; validation 203 prevalence 0.000; test 10 prevalence 0.000.
Template groups that contain any anomaly: 1. Their split placement: {'train': 1}.
Train templates whose time span crosses the test boundary: 1.
Near-duplicate test templates (Jaccard >= 0.8): 7 of 8. Jaccard >= 0.5: 8. Median nearest-train Jaccard 1.000.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| random_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| tfidf_logreg | Not evaluated — ground-truth labels required | | | | | | | | |

isolation_forest: The held-out test set contains one class, so accuracy is not reported.
isolation_forest after removing near-duplicates: Same model and validation threshold, with near-duplicate test templates removed. n=2.
random_forest: Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one.
tfidf_logreg: Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one.

## hadoop

Unit: application. abnormal_label.txt marks each application Normal or a failure type (machine down, network disconnection, disk full). Failure types are binary anomalies. They are not LOW/MEDIUM/HIGH/CRITICAL labels. Applications absent from the label file are excluded.
Population prevalence 0.800 (44 anomaly / 11 normal, 55 template groups).
Anomalous template groups: 44. Groups that contain both labels: 0.
Features available: normalized log text for one instance or application.
Features excluded: raw instance or application id.
Alert-token copies inside the message body: 0. Raw identifiers found inside features: 1.
Each labeled application is one example. At most 80 normalized lines are kept from that application before the application groups are split. Application ids are numeric and are replaced before grouping.

### realistic_group

Template groups were assigned with stratification on the majority label before any sampling. Each group is in train, validation, or test only.
Full split before the row cap: train prevalence 0.788 (26 / 33 rows); validation prevalence 0.818 (9 / 11 rows); test prevalence 0.818 (9 / 11 rows); population prevalence 0.800 (44 / 55 rows).
Evaluated rows: train 33 prevalence 0.788; validation 11 prevalence 0.818; test 11 prevalence 0.818.
Template groups that contain any anomaly: 44. Their split placement: {'test': 9, 'train': 26, 'validation': 9}.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 11. Jaccard >= 0.5: 11. Median nearest-train Jaccard 0.905.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | evaluated | 0.727 | 0.800 | 0.889 | 0.842 | 0.111 | 0.736 | 1000.000 | -0.191 |
| random_forest | evaluated | 0.818 | 0.818 | 1.000 | 0.900 | 0.167 | 0.753 | 1000.000 | 0.025 |
| tfidf_logreg | evaluated | 0.818 | 0.818 | 1.000 | 0.900 | 0.222 | 0.810 | 1000.000 | 0.499 |
| severity_rank_only | evaluated | 0.818 | 0.818 | 1.000 | 0.900 | 0.500 | 0.818 | 1000.000 | 0.500 |

isolation_forest confusion matrix ['normal', 'anomaly']: [[0, 2], [1, 8]].
isolation_forest calibration ECE 0.000, Brier 0.148. Platt scaling was fit on validation scores only. The raw Isolation Forest score is not a class probability.
isolation_forest after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
isolation_forest at the default threshold 0.0: F1 0.000, FP/1,000 0.000.
random_forest confusion matrix ['normal', 'anomaly']: [[0, 2], [0, 9]].
random_forest calibration ECE 0.428, Brier 0.354. Reliability of P(anomaly) on the test rows. The threshold was not used.
random_forest after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
random_forest at the default threshold 0.5: F1 0.706, FP/1,000 1000.000.
tfidf_logreg confusion matrix ['normal', 'anomaly']: [[0, 2], [0, 9]].
tfidf_logreg calibration ECE 0.318, Brier 0.250. Reliability of P(anomaly) on the test rows. The threshold was not used.
tfidf_logreg after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
tfidf_logreg at the default threshold 0.5: F1 0.533, FP/1,000 1000.000.

### chronological_group

Each template is assigned by its earliest timestamp. Train is the earliest groups, validation the next block, and test the latest groups. A template that starts during training never appears in the test.
Full split before the row cap: train prevalence 0.758 (25 / 33 rows); validation prevalence 0.818 (9 / 11 rows); test prevalence 0.909 (10 / 11 rows); population prevalence 0.800 (44 / 55 rows).
Evaluated rows: train 33 prevalence 0.758; validation 11 prevalence 0.818; test 11 prevalence 0.909.
Template groups that contain any anomaly: 44. Their split placement: {'train': 25, 'validation': 9, 'test': 10}.
Train templates whose time span crosses the test boundary: 0.
Near-duplicate test templates (Jaccard >= 0.8): 8 of 11. Jaccard >= 0.5: 11. Median nearest-train Jaccard 0.905.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | evaluated | 0.909 | 1.000 | 0.900 | 0.947 | 1.000 | 1.000 | 0.000 | -0.187 |
| random_forest | evaluated | 0.818 | 0.900 | 0.900 | 0.900 | 0.800 | 0.981 | 1000.000 | 0.175 |
| tfidf_logreg | evaluated | 0.909 | 0.909 | 1.000 | 0.952 | 0.750 | 0.961 | 1000.000 | 0.490 |
| severity_rank_only | evaluated | 0.909 | 0.909 | 1.000 | 0.952 | 0.500 | 0.909 | 1000.000 | 0.521 |

isolation_forest confusion matrix ['normal', 'anomaly']: [[1, 0], [1, 9]].
isolation_forest calibration ECE 0.091, Brier 0.091. Platt scaling was fit on validation scores only. The raw Isolation Forest score is not a class probability.
isolation_forest after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
isolation_forest at the default threshold 0.0: F1 0.000, FP/1,000 0.000.
random_forest confusion matrix ['normal', 'anomaly']: [[0, 1], [1, 9]].
random_forest calibration ECE 0.400, Brier 0.237. Reliability of P(anomaly) on the test rows. The threshold was not used.
random_forest after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
random_forest at the default threshold 0.5: F1 0.667, FP/1,000 0.000.
tfidf_logreg confusion matrix ['normal', 'anomaly']: [[0, 1], [0, 10]].
tfidf_logreg calibration ECE 0.406, Brier 0.247. Reliability of P(anomaly) on the test rows. The threshold was not used.
tfidf_logreg after removing near-duplicates: Every evaluated test template met the near-duplicate cutoff. n=0.
tfidf_logreg at the default threshold 0.5: F1 0.952, FP/1,000 1000.000.

## thunderbird

Unit: line. Thunderbird uses the same first-token alert label as BGL. This file is the 2,000-line sample, not the full corpus.
Population prevalence 0.000 (0 anomaly / 2000 normal, 824 template groups).
Anomalous template groups: 0. Groups that contain both labels: 0.
Features available: component, level word, and message text.
Features excluded: alert token.
Alert-token copies inside the message body: 0. Raw identifiers found inside features: 0.
Severity rank 0: anomaly prevalence 0.000 (0 anomaly / 1998 normal).
Severity rank 2: anomaly prevalence 0.000 (0 anomaly / 2 normal).

### realistic_group

The labeled rows do not contain both classes, so accuracy is not computed.

| Model | Status | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP / 1,000 normal | Threshold |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| random_forest | Not evaluated — ground-truth labels required | | | | | | | | |
| tfidf_logreg | Not evaluated — ground-truth labels required | | | | | | | | |

isolation_forest: The labeled rows do not contain both classes, so accuracy is not computed.
random_forest: The labeled rows do not contain both classes, so accuracy is not computed.
tfidf_logreg: The labeled rows do not contain both classes, so accuracy is not computed.

### chronological_group

Not used. Fewer than 95% of parsed rows have a timestamp, so a time split would not be a future holdout.

## linux

Linux_2k has no verified ground truth. LOW, MEDIUM, HIGH, and CRITICAL are estimated anomaly-score bands, not validated four-class severity.

## Deployment

These scores are normal versus anomaly. They do not validate LOW, MEDIUM, HIGH, or CRITICAL. Linux_2k has no verified labels, so its bands stay estimated score quantiles. A model is not a deployment candidate here unless a protocol with realistic prevalence, an untouched test set, and a check for near-duplicate templates still keeps false positives low.

BGL corpus prevalence is 0.074. The preserved benchmark reports random forest F1 0.998 on a test set whose anomaly prevalence is 0.719 (5751 of 8000 rows). This run's random group holdout tests at prevalence 0.040: random forest F1 0.706, precision 0.998, recall 0.546, FP/1,000 normal 0.052; logistic regression F1 0.626 with FP/1,000 0.000. Removing near-duplicate test templates drops random-forest F1 to 0.433. The chronological holdout is the cleaner check: median nearest-train Jaccard is 0.000, random forest F1 0.916 and logistic regression F1 0.904, with FP/1,000 0.053 and 0.000. Isolation Forest does not transfer. Its validation threshold scores F1 0.101 with FP/1,000 999.736 on the future split, while the default score threshold of 0 scores F1 0.501 and FP/1,000 72.085. On the random split its F1 is 0.122. Every BGL anomaly in this parse has severity rank 3. The severity-only baseline recalls 1.000 of anomalies at precision 0.192 and FP/1,000 177.243, below the text models on precision. Chronological random forest and logistic regression are the only BGL results that look like generalization. They still do not validate four-class severity.

HDFS corpus prevalence is 0.029. The preserved benchmark reports random forest F1 0.996 on a test set whose anomaly prevalence is 0.285 (2277 of 8000 rows). Chronological evaluation is not meaningful: Fewer than 95% of parsed rows have a timestamp, so a time split would not be a future holdout. The group holdout's full test prevalence is 0.094 and the evaluated cap is 0.093, above the corpus rate because whole groups differ in size. Random forest F1 is 0.969 with FP/1,000 5.182; logistic regression F1 is 0.973 with FP/1,000 5.624. After near-duplicate removal, random-forest F1 is 0.961. The single train-chosen event id E7 has test F1 0.393 and recall 0.245, so the text models are not that one token. Isolation Forest F1 is 0.261 with FP/1,000 323.465. There is no future-time holdout for HDFS in this run.

OpenStack has 4 anomalous instances and 2065 normal instances. Majority-anomaly templates: 0. Templates that contain any anomaly: 1, placed {'train': 1}. The evaluated test prevalence is 0.000. Supervised models were refused: Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one. Isolation Forest was fit and then not scored: The held-out test set contains one class, so accuracy is not reported. Median nearest-train Jaccard on the test templates is 1.000. Four anomalous instances inside one mixed template do not support a supervised deployment claim.

Hadoop has 55 application templates, 44 anomalous and 11 normal. The random holdout scores 11 test applications at prevalence 0.818. Random forest F1 is 0.900 with FP/1,000 1000.000 and ROC-AUC 0.167. Median nearest-train Jaccard is 0.905. Near-duplicate removal leaves n=0: Every evaluated test template met the near-duplicate cutoff. Raw identifiers left in features: 1. The chronological Isolation Forest result, F1 0.947 on 11 rows, is one small draw and the same near-duplicate filter empties that test too. Hadoop does not support deployment.

Thunderbird_2k has 0 anomalous rows out of 2000. Accuracy is not computed. Fewer than 95% of parsed rows have a timestamp, so a time split would not be a future holdout. The full Thunderbird corpus was not evaluated.
