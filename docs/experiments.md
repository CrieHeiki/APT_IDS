# Archived experiments and findings

[← README](../README.md) · [Architecture](architecture.md) · [Limitations](limitations.md)

This is a **report of saved evidence**, not a claim that new attack traffic, retraining, or fresh model evaluation was performed during the GitHub documentation update.

## 1. Evidence sources and boundaries

| Evidence | Source | Measures (or records) |
| --- | --- | --- |
| Offline test-set report | [`artifacts/report_ready/03_test_classification_report.png`](../artifacts/report_ready/03_test_classification_report.png) | Multiclass performance on saved test windows |
| Validation calibration | [`artifacts/threshold.json`](../artifacts/threshold.json) | Threshold selection on saved validation setup |
| Reconnaissance baseline and variants | [`generalization_test/results/results.csv`](../generalization_test/results/results.csv) | NFStream-adapter window predictions during controlled lab runs |
| Experiment raw evidence | [`generalization_test/logs/`](../generalization_test/logs/) | Saved adapter outputs and run-status records |
| Freeze record | [`generalization_test/frozen/`](../generalization_test/frozen/) | Evaluation artifact snapshot, SHA256SUMS and environment notes |
| CICFlowMeter failed runtime | Former root `logs/predictions.jsonl` in the **original supplied ZIP** | Adapter/schema errors, **not** successful predictions; raw runtime logs excluded from cleaned repository |

## 2. Offline model test (archived report)

The retained figure reports these values; they have **not** been recalculated from the full test dataset, which is not included.

| Class | Precision | Recall | F1 | Support (windows) |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.9983 | 0.9919 | 0.9951 | 79,520 |
| COVER UP | 0.6667 | 0.3810 | 0.4848 | 21 |
| DATA EXFILTRATION | 0.8989 | 0.7143 | 0.7960 | 336 |
| ESTABLISH FOOTHOLD | 0.9333 | 0.9890 | 0.9604 | 1,090 |
| LATERAL MOVEMENT | 0.8979 | 0.9802 | 0.9372 | 5,515 |
| RECONNAISSANCE | 0.9452 | 0.9747 | 0.9597 | 513 |
| **Overall accuracy** | | | **0.9898** | **86,995** |
| **Macro average** | 0.8900 | 0.8385 | **0.8555** | **86,995** |

The large BENIGN support contributes heavily to overall accuracy; the very low support and recall for COVER UP make macro F1 and per-class results necessary context.

Supporting figures: [counts confusion matrix](../artifacts/report_ready/01_test_confusion_matrix_counts.png), [normalized confusion matrix](../artifacts/report_ready/02_test_confusion_matrix_normalized.png), [archived training curves](../artifacts/report_ready/04_training_curves.png).

## 3. Lab experiment design from repository

Recorded controls are stated in [`TEST_RULES.txt`](../generalization_test/TEST_RULES.txt): freeze model and preprocessing, avoid model-guided tuning of variants, preserve correct and incorrect outcomes, separate baseline from generalization and avoid interfering traffic while 50-flow windows accumulate.

The experiment shell scripts invoke the **NFStream** adapter inside [`frozen/snapshot_20260728_194825/`](../generalization_test/frozen/snapshot_20260728_194825/). They do **not** use the CICFlowMeter Python wrapper. The archived scripts contain original absolute filesystem paths, victim/Kali IPs and interface names; these are **records of the test environment**, not a portable one-command installer.

### Recorded runs by variant

The table below is a direct aggregation of the existing `results.csv` (distinct `run_id` and number of CSV prediction rows):

| Group | Variant in CSV | Distinct runs | Windows predicted RECONNAISSANCE |
| --- | --- | ---: | ---: |
| Baseline | `nmap_syn_t4_ports_1_300` | 10 | 199 |
| Variants | `R1_SYN_50_T4` | 1 | 1 |
| Variants | `R2_SYN_1000_T4` | 2 | 99 |
| Variants | `R3_CONNECT_300_T4` | 2 | 52 |
| Variants | `R4_SYN_100_SLOW` | 7 | 42 |
| Variants | `R5_SYN_TOP100_T3` | 2 | 12 |
| **Total** | | **24** | **405** |

- Baseline: **10 runs, 199 windows**, all saved `predicted_stage=RECONNAISSANCE`, `correct_stage=1`.
- Variants: **14 runs, 206 windows**, all saved `predicted_stage=RECONNAISSANCE`, `correct_stage=1`.
- Total: **405/405 saved reconnaissance-labeled windows** match `true_stage=RECONNAISSANCE` in the CSV.

These are **recorded positive-scenario classifications**, not estimates of global true-positive rate or intrusion detection accuracy. Multiple windows can originate from a single run and overlap; thus `405/405` is not 405 independent attack detections. The existing CSV does not supply a corresponding BENIGN-only baseline for estimating false positives in this lab.

### Latency caveat

Baseline rows have a blank `detection_latency_seconds` field and notes containing `latency_not_instrumented`. The variants contain **206 entries of `0.000000`**. In [`run_recon_variants_ubuntu.sh`](../generalization_test/scripts/run_recon_variants_ubuntu.sh), latency is computed with `max(0.0, prediction - scan_start)` using timestamps exchanged between separate systems. The stored timing/status evidence is not sufficient to validate clock synchronization. **Do not report 0 seconds as measured detection latency.**

### Additional scripts without matching archived run evidence

Files including [`scripts/test_data_exfil_v2.py`](../scripts/test_data_exfil_v2.py), [`scripts/test_data_exfil_v3.py`](../scripts/test_data_exfil_v3.py), and [`scripts/test_foothold_v5.py`](../scripts/test_foothold_v5.py) exist in the repository. Their presence documents test-scenario code; it does **not** establish that equivalent successful outcomes were captured in `generalization_test/results/results.csv`, which contains **RECONNAISSANCE** rows only.

## 4. Reproducibility and what was not recreated

The original [`frozen`](../generalization_test/frozen/) directory records a frozen artifact set and SHA-256 list. It has been left intact. `experiment.env`, `verify_frozen.sh`, and runtime config still point to **the original VM**; the contents are useful archival provenance but not a turnkey environment on another machine. No new capture, model retraining, attack run, or timing test was performed when organizing these documents.

## 5. Responsible interpretation

Supported conclusions:

- The saved model test artifact reports strong aggregate accuracy, with uneven per-class scores.
- Saved NFStream reconnaissance runs recorded predictions matching the expected RECONNAISSANCE label for 405 windows in 24 runs.
- The supplied CICFlowMeter runtime **did not** reach successful inference because required features were absent in its observed input.

Unsupported conclusions from current saved evidence:

- Production-grade or generalizable detection across arbitrary environments.
- Measured zero-second end-to-end detection latency.
- Low false-positive rate during the saved NFStream reconnaissance lab trials.
- End-to-end CICFlowMeter inference success or validated deployment of all six classes.
