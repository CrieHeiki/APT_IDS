#!/usr/bin/env bash

set -euo pipefail

source \
"$HOME/Downloads/APT_IDS_VM_DEPLOY/generalization_test/experiment.env"

CONTROL_PORT=5555
RESPONSE_PORT=5556
TOTAL_RUNS=50

LOG_DIR="$TEST_ROOT/logs/recon_variants"

mkdir -p "$LOG_DIR"

sudo -v

"$TEST_ROOT/scripts/verify_frozen.sh" \
    >/tmp/verify_recon_variants.log

cleanup_adapter() {
    sudo pkill -TERM \
        -f '[n]fstream_adapter_fast.py' \
        2>/dev/null || true

    sleep 2
}

receive_control_message() {
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

sock.settimeout(900)
sock.bind(("0.0.0.0", port))

try:
    data, address = sock.recvfrom(8192)
except socket.timeout:
    raise SystemExit("TIMEOUT")

message = data.decode(
    "utf-8",
    errors="replace",
).strip()

print(message)
print(address[0])

sock.close()
PY
}

send_response() {
    local response="$1"

    python3 - \
        "$KALI_IP" \
        "$RESPONSE_PORT" \
        "$response" \
        <<'PY'
import socket
import sys

destination = sys.argv[1]
port = int(sys.argv[2])
message = sys.argv[3].encode("utf-8")

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM,
)

sock.sendto(
    message,
    (destination, port),
)

sock.close()
PY
}

cleanup_adapter

echo
echo "=========================================="
echo " RECONNAISSANCE GENERALIZATION — UBUNTU"
echo " Snapshot : $SNAPSHOT_HASH"
echo " Tổng run : $TOTAL_RUNS"
echo "=========================================="

for run_number in $(seq 1 "$TOTAL_RUNS"); do
    echo
    echo "------------------------------------------"
    echo "Chờ Kali gửi run $run_number/$TOTAL_RUNS"
    echo "------------------------------------------"

    CONTROL_RESULT="$(receive_control_message)"

    MESSAGE="$(printf '%s\n' "$CONTROL_RESULT" | sed -n '1p')"
    SIGNAL_IP="$(printf '%s\n' "$CONTROL_RESULT" | sed -n '2p')"

    IFS='|' read -r \
        ACTION \
        RUN_ID \
        SCENARIO \
        VARIANT \
        PROTOCOL \
        EXPECTED_FLOW_COUNT \
        <<< "$MESSAGE"

    if [ "$ACTION" != "GO" ]; then
        echo "Tín hiệu không hợp lệ: $MESSAGE"
        exit 1
    fi

    if [ "$SIGNAL_IP" != "$KALI_IP" ]; then
        echo "CẢNH BÁO: tín hiệu đến từ $SIGNAL_IP"
    fi

    echo "Run ID       : $RUN_ID"
    echo "Variant      : $VARIANT"
    echo "Protocol     : $PROTOCOL"
    echo "Expected flow: $EXPECTED_FLOW_COUNT"

    RAW_LOG="$LOG_DIR/${RUN_ID}_adapter.log"
    STATUS_FILE="$LOG_DIR/${RUN_ID}_status.txt"
    FIRST_PRED_FILE="$LOG_DIR/${RUN_ID}_first_prediction.txt"

    rm -f \
        "$RAW_LOG" \
        "$STATUS_FILE" \
        "$FIRST_PRED_FILE"

    cleanup_adapter

    ADAPTER_START="$(date +%s.%N)"

    echo "Khởi động adapter..."

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

    sleep 7

    if ! pgrep \
        -f '[n]fstream_adapter_fast.py' \
        >/dev/null
    then
        echo "Adapter đã thoát."
        cat "$RAW_LOG"
        exit 1
    fi

    # Ghi thời điểm dự đoán đầu tiên.
    (
        while pgrep \
            -f '[n]fstream_adapter_fast.py' \
            >/dev/null
        do
            if grep -q \
                '"probabilities"' \
                "$RAW_LOG" \
                2>/dev/null
            then
                date +%s.%N \
                    > "$FIRST_PRED_FILE"
                exit 0
            fi

            sleep 0.2
        done
    ) &

    WATCHER_PID=$!

    send_response "READY|$RUN_ID"

    echo "Adapter sẵn sàng, chờ Kali hoàn thành scan..."

    DONE_RESULT="$(receive_control_message)"

    DONE_MESSAGE="$(
        printf '%s\n' "$DONE_RESULT" |
        sed -n '1p'
    )"

    DONE_IP="$(
        printf '%s\n' "$DONE_RESULT" |
        sed -n '2p'
    )"

    IFS='|' read -r \
        DONE_ACTION \
        DONE_RUN_ID \
        SCAN_START \
        SCAN_END \
        <<< "$DONE_MESSAGE"

    if [ "$DONE_ACTION" != "DONE" ]; then
        echo "Tín hiệu hoàn thành không hợp lệ:"
        echo "$DONE_MESSAGE"
        exit 1
    fi

    if [ "$DONE_RUN_ID" != "$RUN_ID" ]; then
        echo "Run ID không khớp:"
        echo "Expected: $RUN_ID"
        echo "Received: $DONE_RUN_ID"
        exit 1
    fi

    echo "Kali đã hoàn thành scan."

    # Chờ adapter xử lý packet kích hoạt và xuất
    # các cửa sổ còn lại.
    sleep 12

    cleanup_adapter

    kill "$WATCHER_PID" 2>/dev/null || true
    wait "$WATCHER_PID" 2>/dev/null || true

    ADAPTER_END="$(date +%s.%N)"

    FIRST_PREDICTION=""

    if [ -s "$FIRST_PRED_FILE" ]; then
        FIRST_PREDICTION="$(cat "$FIRST_PRED_FILE")"
    fi

    DETECTION_LATENCY=""

    if (
        [ -n "$FIRST_PREDICTION" ] &&
        [ -n "$SCAN_START" ]
    ); then
        DETECTION_LATENCY="$(
            python3 - \
                "$FIRST_PREDICTION" \
                "$SCAN_START" \
                <<'PY'
import sys

prediction = float(sys.argv[1])
scan_start = float(sys.argv[2])

print(
    f"{max(0.0, prediction - scan_start):.6f}"
)
PY
        )"
    fi

    {
        echo "run_id=$RUN_ID"
        echo "variant=$VARIANT"
        echo "protocol=$PROTOCOL"
        echo "adapter_start=$ADAPTER_START"
        echo "scan_start=$SCAN_START"
        echo "scan_end=$SCAN_END"
        echo "first_prediction=$FIRST_PREDICTION"
        echo "detection_latency=$DETECTION_LATENCY"
        echo "adapter_end=$ADAPTER_END"
    } > "$STATUS_FILE"

    python3 - \
        "$RAW_LOG" \
        "$RESULTS_CSV" \
        "$RUN_ID" \
        "$SCENARIO" \
        "$VARIANT" \
        "$PROTOCOL" \
        "$EXPECTED_FLOW_COUNT" \
        "$DETECTION_LATENCY" \
        "$SNAPSHOT_HASH" \
        "$SCAN_START" \
        "$SCAN_END" \
        <<'PY'
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


log_path = Path(sys.argv[1])
csv_path = Path(sys.argv[2])

run_id = sys.argv[3]
scenario = sys.argv[4]
variant = sys.argv[5]
protocol = sys.argv[6]
expected_flow_count = sys.argv[7]
detection_latency = sys.argv[8]
snapshot_hash = sys.argv[9]
scan_start = sys.argv[10]
scan_end = sys.argv[11]

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

        probabilities = record.get(
            "probabilities"
        )

        if (
            isinstance(probabilities, dict)
            and probabilities
        ):
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

    notes = (
        f"scan_start={scan_start};"
        f"scan_end={scan_end}"
    )

    rows.append([
        run_id,
        timestamp,
        "RECONNAISSANCE",
        scenario,
        variant,
        protocol,
        expected_flow_count,
        0,
        predicted_stage,
        f"{confidence:.8f}",
        f"{attack_score:.8f}",
        detection_latency,
        window_index,
        int(
            predicted_stage
            == "RECONNAISSANCE"
        ),
        int(attack_score >= 0.4),
        notes,
        snapshot_hash,
    ])

if not rows:
    rows.append([
        run_id,
        timestamp,
        "RECONNAISSANCE",
        scenario,
        variant,
        protocol,
        expected_flow_count,
        0,
        "NO_OUTPUT",
        "",
        "",
        detection_latency,
        0,
        0,
        0,
        (
            f"no_prediction;"
            f"scan_start={scan_start};"
            f"scan_end={scan_end}"
        ),
        snapshot_hash,
    ])

with csv_path.open(
    "a",
    newline="",
    encoding="utf-8",
) as file:
    csv.writer(file).writerows(rows)

print()
print(f"Run: {run_id}")
print(f"Variant: {variant}")
print(f"Prediction windows: {len(predictions)}")

if predictions:
    stages = Counter(
        record.get("stage", "UNKNOWN")
        for record in predictions
    )

    majority_stage, majority_count = (
        stages.most_common(1)[0]
    )

    print(
        f"Majority: {majority_stage} "
        f"({majority_count}/{len(predictions)})"
    )

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
            f"confidence="
            f"{100 * float(ordered[0][1]):.1f}% | "
            f"attack="
            f"{100 * float(record.get('attack_score', 0)):.1f}%"
        )
else:
    print("Không có dự đoán.")
PY

    send_response "FINISHED|$RUN_ID"

    echo "Hoàn tất run $run_number/$TOTAL_RUNS."
done

cleanup_adapter

echo
echo "=========================================="
echo " ĐÃ HOÀN TẤT 50 RECON VARIANT RUN"
echo " Kết quả: $RESULTS_CSV"
echo "=========================================="
