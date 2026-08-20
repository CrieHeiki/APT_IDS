#!/usr/bin/env bash

set -euo pipefail

ENV_FILE="$HOME/Downloads/APT_IDS_VM_DEPLOY/generalization_test/experiment.env"

source "$ENV_FILE"

RUN_COUNT=10
CONTROL_PORT=5555
LOG_DIR="$TEST_ROOT/logs/recon_baseline"

mkdir -p "$LOG_DIR"

sudo -v

"$TEST_ROOT/scripts/verify_frozen.sh" \
    >/tmp/verify_recon_frozen.log

echo
echo "=========================================="
echo " RECONNAISSANCE BASELINE — UBUNTU RUNNER"
echo " Snapshot: $SNAPSHOT_HASH"
echo " Số lần chạy: $RUN_COUNT"
echo "=========================================="
echo

cleanup_adapter() {
    sudo pkill -TERM \
        -f '[n]fstream_adapter_fast.py' \
        2>/dev/null || true

    sleep 2
}

cleanup_adapter

for run_number in $(seq 1 "$RUN_COUNT"); do
    echo
    echo "------------------------------------------"
    echo "Đang chờ Kali bắt đầu lần $run_number/$RUN_COUNT"
    echo "UDP control port: $CONTROL_PORT"
    echo "------------------------------------------"

    SIGNAL="$(
        python3 - "$CONTROL_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM,
)

sock.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1,
)

sock.bind(("0.0.0.0", port))

data, address = sock.recvfrom(2048)

message = data.decode(
    "utf-8",
    errors="replace",
).strip()

print(
    f"{message} {address[0]}"
)

sock.close()
PY
    )"

    read -r ACTION RUN_ID SIGNAL_IP <<< "$SIGNAL"

    if [ "$ACTION" != "GO" ]; then
        echo "Tín hiệu không hợp lệ: $SIGNAL"
        exit 1
    fi

    echo "Đã nhận tín hiệu:"
    echo "  Run ID : $RUN_ID"
    echo "  Kali IP: $SIGNAL_IP"

    if [ "$SIGNAL_IP" != "$KALI_IP" ]; then
        echo "CẢNH BÁO: tín hiệu không đến từ $KALI_IP"
    fi

    RAW_LOG="$LOG_DIR/${RUN_ID}_adapter.log"
    STATUS_FILE="$LOG_DIR/${RUN_ID}_status.txt"

    rm -f "$RAW_LOG" "$STATUS_FILE"

    cleanup_adapter

    # Tín hiệu UDP đã đến trước khi adapter chạy nên không
    # đi vào cửa sổ flow của model.
    sleep 2

    echo "Khởi động adapter cho $RUN_ID..."

    ADAPTER_START="$(
        date +%s.%N
    )"

    sudo env \
        CUDA_VISIBLE_DEVICES=-1 \
        TF_CPP_MIN_LOG_LEVEL=3 \
        PYTHONFAULTHANDLER=1 \
        "$PY" -X faulthandler -u \
        "$FROZEN_ARTIFACTS/nfstream_adapter_fast.py" \
        --bundle "$FROZEN_ARTIFACTS" \
        --source "$IFACE" \
        >"$RAW_LOG" 2>&1 &

    ADAPTER_LAUNCH_PID=$!

    echo "Adapter launch PID: $ADAPTER_LAUNCH_PID"
    echo "Chờ Kali quét và kích hoạt xuất flow..."

    PREDICTION_FOUND=0
    DETECT_TIME=""

    # Tối đa 70 giây cho mỗi lần chạy.
    for second in $(seq 1 70); do
        sleep 1

        if grep -q '"probabilities"' "$RAW_LOG" 2>/dev/null; then
            PREDICTION_FOUND=1
            DETECT_TIME="$(date +%s.%N)"

            echo "Đã nhận dự đoán sau khoảng $second giây."
            break
        fi

        if ! pgrep \
            -f '[n]fstream_adapter_fast.py' \
            >/dev/null
        then
            echo "Adapter đã thoát trước khi có dự đoán."
            break
        fi
    done

    if [ "$PREDICTION_FOUND" -eq 1 ]; then
        # Thu thêm các cửa sổ còn lại.
        sleep 5
    fi

    cleanup_adapter

    ADAPTER_END="$(
        date +%s.%N
    )"

    printf '%s\n' \
        "run_id=$RUN_ID" \
        "adapter_start=$ADAPTER_START" \
        "prediction_detected=$DETECT_TIME" \
        "adapter_end=$ADAPTER_END" \
        "prediction_found=$PREDICTION_FOUND" \
        > "$STATUS_FILE"

    python3 - \
        "$RAW_LOG" \
        "$RESULTS_CSV" \
        "$RUN_ID" \
        "$SNAPSHOT_HASH" \
        "$PREDICTION_FOUND" \
        <<'PY'
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


log_path = Path(sys.argv[1])
csv_path = Path(sys.argv[2])
run_id = sys.argv[3]
snapshot_hash = sys.argv[4]
prediction_found = int(sys.argv[5])

predictions = []

if log_path.exists():
    for line in log_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        probabilities = record.get("probabilities")

        if not isinstance(probabilities, dict):
            continue

        if not probabilities:
            continue

        predictions.append(record)

timestamp = datetime.now(
    timezone.utc
).astimezone().isoformat()

rows = []

for window_index, record in enumerate(
    predictions,
    start=1,
):
    probabilities = record["probabilities"]

    predicted_stage = str(
        record.get("stage", "UNKNOWN")
    )

    confidence = max(
        float(value)
        for value in probabilities.values()
    )

    attack_score = float(
        record.get("attack_score", 0.0)
    )

    rows.append([
        run_id,
        timestamp,
        "RECONNAISSANCE",
        "baseline_recon",
        "nmap_syn_t4_ports_1_300",
        "TCP_SYN",
        300,
        0,
        predicted_stage,
        f"{confidence:.8f}",
        f"{attack_score:.8f}",
        "",
        window_index,
        int(
            predicted_stage
            == "RECONNAISSANCE"
        ),
        int(attack_score >= 0.4),
        "baseline;latency_not_instrumented",
        snapshot_hash,
    ])

if not rows:
    rows.append([
        run_id,
        timestamp,
        "RECONNAISSANCE",
        "baseline_recon",
        "nmap_syn_t4_ports_1_300",
        "TCP_SYN",
        300,
        0,
        "NO_OUTPUT",
        "",
        "",
        "",
        0,
        0,
        0,
        (
            "adapter_no_prediction"
            if not prediction_found
            else "prediction_parse_error"
        ),
        snapshot_hash,
    ])

with csv_path.open(
    "a",
    newline="",
    encoding="utf-8",
) as csv_file:
    writer = csv.writer(csv_file)
    writer.writerows(rows)

print()
print(f"Run: {run_id}")

for index, record in enumerate(
    predictions,
    start=1,
):
    probabilities = record["probabilities"]

    ordered = sorted(
        probabilities.items(),
        key=lambda item: float(item[1]),
        reverse=True,
    )

    print(
        f"  Window {index}: "
        f"{record.get('stage')} | "
        f"attack={100 * float(record.get('attack_score', 0)):.0f}% | "
        f"confidence={100 * float(ordered[0][1]):.0f}%"
    )

    print(
        "    "
        + " | ".join(
            f"{name}={100 * float(value):.0f}%"
            for name, value in ordered
        )
    )

if not predictions:
    print("  Không có dự đoán.")

print(f"  Log: {log_path}")
PY

    echo
    echo "Hoàn tất lần $run_number/$RUN_COUNT."
done

cleanup_adapter

echo
echo "=========================================="
echo " ĐÃ HOÀN TẤT 10 LẦN RECON BASELINE"
echo " Kết quả: $RESULTS_CSV"
echo " Log: $LOG_DIR"
echo "=========================================="
