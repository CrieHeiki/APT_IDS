# Known limitations and scope of evidence

[← README](../README.md) · [Architecture](architecture.md) · [Experiments](experiments.md)

This is a documentation-only inventory of issues visible in the supplied repository. It is **not** a request to rebuild the lab or rerun attacks.

## 1. CICFlowMeter selected-feature mismatch — observed failure

The root runtime log (`logs/predictions.jsonl`) in the **original submitted ZIP** contained **14,986 JSONL records**, all reporting a preprocessing/mapping error, with **zero populated `predicted_apt_stage` values**. The reported missing selected features were:

```text
src2dst_rst_packets
dst2src_ack_packets
```

The exact identifiers are `src2dst_rst_packets` and `dst2src_ack_packets`.

[`app/feature_adapter.py`](../app/feature_adapter.py) is deliberately fail-closed: when the source CSV cannot provide a required selected feature, it raises `FeatureMappingError` rather than silently fabricating the value. These directional TCP flag features are required by the saved 21-feature selection; a generic forward/backward aggregate column cannot be treated as equivalent without evidence.

**Implication:** the supplied runtime log does not support a claim of successful live/PCAP CICFlowMeter classification. Model test metrics and NFStream inference logs should not be used to conceal this gap. The clean GitHub copy omits the large, raw, machine-specific root runtime log; this *aggregate finding and provenance note* are retained.

## 2. Distinct input extractors

The main wrapper uses **CICFlowMeter CSV + a controlled alias adapter**. The archived reconnaissance experiments use **NFStream-derived fields** from a separate adapter. Equal model files are not enough to demonstrate interchangeable feature values or functional parity. See [Architecture](architecture.md).

## 3. Model performance and dataset constraints

- `COVER UP`: **21** test windows, **38.10% recall**, **48.48% F1** in the archived class report. Reliability for rare classes is not demonstrated by the headline accuracy.
- Offline test distribution: **79,520 BENIGN** out of **86,995 windows**; accuracy alone is susceptible to class imbalance.
- The original training dataset and training notebook are not included. Saved split metadata and methods can be described, but the full training/evaluation process is not reproducible from this repo alone.
- The impact of source-network changes, temporal overlap, and cross-dataset/domain shifts is not established by the archived reports.

## 4. Experiment interpretation constraints

- The saved `results.csv` covers reconnaissance baseline and variants only. It does not demonstrate equivalent lab performance for data exfiltration, foothold, lateral movement, cover-up, or benign flows.
- The saved **405** windows come from **24** runs and are correlated; they should not be advertised as 405 independent attack trials.
- No BENIGN-only companion run results are present in that CSV, preventing calculation of a lab false-positive rate from those rows.
- Baseline latency is uninstrumented; variant latency is recorded as **0** through a clamp in the script and lacks a trustworthy synchronized-clock basis. It is **not** evidence of instantaneous detection.

## 5. Environment portability

- [`config/config.yaml`](../config/config.yaml), [`generalization_test/experiment.env`](../generalization_test/experiment.env) and selected experiment scripts retain original absolute VM paths and interface names. Changing machines requires configuration changes, which are deliberately **out of scope** here.
- The project does not bundle CICFlowMeter or the placeholder PCAP path from the old README.
- The frozen snapshot's environment record and verification script are archival artifacts; the snapshot is preserved, not converted into a new setup process.

## 6. Artifact integrity and dependency compatibility

### A pre-existing deployment manifest discrepancy

An integrity check against [`artifacts/deployment_manifest.json`](../artifacts/deployment_manifest.json) confirmed **32 of its 33 listed files match** the listed SHA-256 values. The one exception is `artifacts/nfstream_adapter.py`:

| Check | Value |
| --- | --- |
| Manifest size / SHA-256 | `2139` bytes / `38a98f5fbf122a78d88910727c8cb30a6f8b75111a9eb4b3f76aa610e509374d` |
| Actual archived size / SHA-256 | `2205` bytes / `ff875069ab25fd6e450e80a4d62eca00384461026fa49b3b02eaeb19b341f1c7` |
| Frozen snapshot record | SHA-256 matches the **actual** archived file |

The **original ZIP already has the same mismatch**. The frozen snapshot's `SHA256SUMS.txt` was checked independently: **50/50 checksums match**. To preserve archival provenance, this documentation-only cleanup did not rewrite the manifest, adapter or snapshot. The manifest should **not** be described as fully verified.

### Review-environment unit tests (not production validation)

An inspection run of the existing tests with **Python 3.13.5**, **scikit-learn 1.8.0**, and no TensorFlow available resulted in **7 passed, 2 skipped, 2 failed**. Both failed preprocessing tests raise `AttributeError: 'SimpleImputer' object has no attribute '_fill_dtype'` while loading/translating a `SimpleImputer` saved by **scikit-learn 1.6.1**. The original [`requirements.txt`](../requirements.txt) pins `scikit-learn==1.6.1` and the original installer uses Python 3.12. Consequently, these two failures are evidence of **review-environment artifact incompatibility**, not a validation that the pinned deployment environment fails. The TensorFlow-dependent checks were skipped in the review environment; end-to-end execution has not been verified.

No dependency pins, serialized objects, application code, or tests were modified as part of this documentation work.

## 7. Changes intentionally excluded

No code refactoring, model alteration, new detection rules, traffic generation, model retraining, extra test runs, or environment reconstruction were introduced. The public-facing documentation describes what the **existing materials** show and explicitly distinguishes evidence from implementation goals.
