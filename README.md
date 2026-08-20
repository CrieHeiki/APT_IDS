# APT IDS VM Deployment

This project is a self-contained Ubuntu/Linux deployment wrapper for the trained
APT stage classifier. It does not retrain the model.

## Selected Artifacts

The deployed artifacts are copied into `artifacts/` from the compatible
deployment bundle:

- `model.keras`: CNN-BiLSTM-MultiHeadAttention v4.5 Safe.
- `preprocessor_bundle.joblib`: imputer, scaler, label encoder, feature schema,
  selected feature indices, frequency maps, z-score clipping stats, and config.
- `threshold.json`: validation-calibrated attack score threshold `0.4`.
- `feature_schema.json`, `preprocessing_config.json`, `label_mapping.csv`, and
  related manifest files for inspection.

The model input is one sequence of shape `(50, 21)` with stride `10`.
Classes are `BENIGN`, `COVER UP`, `DATA EXFILTRATION`,
`ESTABLISH FOOTHOLD`, `LATERAL MOVEMENT`, and `RECONNAISSANCE`.

## Pipeline

`interface/pcap -> CICFlowMeter -> CSV reader -> controlled column mapping ->
schema check -> training preprocessing artifacts -> sliding window ->
Keras model -> prior correction and threshold rule -> JSONL logs`.

The training schema uses NFStream-style feature names. `app/feature_adapter.py`
maps CICFlowMeter column names into that schema only when a controlled mapping is
available. Missing selected features raise an error; the app does not silently
fill missing required features.

## Ubuntu Install

Install OS packages as appropriate for your VM and CICFlowMeter build, for
example Java and packet capture libraries:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-dev build-essential default-jre tcpdump
```

Then set up Python dependencies:

```bash
cd APT_IDS_VM_DEPLOY
bash scripts/install_ubuntu.sh
```

Use Python 3.12 or 3.13 for the deployment environment. The artifacts were
saved with TensorFlow `2.20.0`, Keras `3.13.2`, and scikit-learn `1.6.1`; the
root `requirements.txt` pins the versions that matter for model and
preprocessor compatibility.

Install CICFlowMeter separately. If your build uses a Java jar, edit
`config/config.yaml` to point at it, for example:

```yaml
cicflowmeter:
  commands:
    live: ["java", "-jar", "tools/CICFlowMeter.jar", "-i", "{interface}", "-c", "{output_dir}"]
    pcap: ["java", "-jar", "tools/CICFlowMeter.jar", "-f", "{pcap}", "-c", "{output_dir}"]
```

## Interface Check

List interfaces before live capture:

```bash
ip -br link
ip -br addr
```

Packet capture normally requires capabilities or an elevated shell for the
external CICFlowMeter process. The Python application itself does not call
`sudo`.

## Run

Live mode:

```bash
python -m app.main --mode live --interface ens33
```

or:

```bash
bash scripts/run_live.sh ens33
```

PCAP mode:

```bash
python -m app.main --mode pcap --pcap samples/test.pcap
```

or:

```bash
bash scripts/run_pcap.sh samples/test.pcap
```

Outputs are printed to the terminal and appended to `logs/predictions.jsonl`.
CSV read checkpoints are stored in `state/flow_reader_state.json` so live mode
does not re-predict old rows after each poll.

## Schema Check

Use this after configuring CICFlowMeter to verify column compatibility:

```bash
python -m app.main --mode pcap --pcap samples/test.pcap --schema-check-only
```

If your CICFlowMeter version does not emit directional `Fwd RST` or `Bwd ACK`
columns, the model's selected features cannot be reproduced exactly from that
CSV alone. Configure equivalent aliases in `config/config.yaml` only when your
CICFlowMeter build really provides those columns.

## Tests

After installing dependencies:

```bash
python -m pytest
python -m compileall app tests
```

The tests cover artifact loading, model input shape, selected feature order,
CICFlowMeter mapping, preprocessing dimensions, fake-batch inference, sliding
window stride, label mapping, and missing/NaN/infinity handling.
