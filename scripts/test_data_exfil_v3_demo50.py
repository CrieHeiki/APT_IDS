import concurrent.futures
import os
import time

from scapy.all import IP, TCP, Raw, conf, get_if_addr


INTERFACE = "enp0s3"
SOURCE_IP = get_if_addr(INTERFACE)
DESTINATION_IP = "192.168.56.20"
DESTINATION_PORT = 3306

# Các flow hoàn thành cách nhau 250 ms để NFStream xuất đúng thứ tự.
BASE_END_TIME = 80.0
END_SPACING = 0.25


def tiny_flow(duration_ms):
    return {
        "sizes": [54, 88],
        "gaps": [duration_ms / 1000.0],
    }


def special_1467():
    # 12 packet, tổng 1467 byte, max=357,
    # mean=122.25, std≈98.62.
    return {
        "sizes": [
            357, 307, 92, 80,
            79, 79, 79, 79,
            79, 79, 79, 78,
        ],
        # 11 gap, tổng 26 ms, max 14 ms.
        "gaps": [
            0.014, 0.002, 0.002,
            0.001, 0.001, 0.001, 0.001,
            0.001, 0.001, 0.001, 0.001,
        ],
    }


def special_363(duration_ms):
    # 4 packet: tổng=363, max=149,
    # mean=90.75, std≈45.92.
    small_gap = (
        duration_ms - 63208
    ) / 2 / 1000.0

    return {
        "sizes": [54, 54, 106, 149],
        "gaps": [
            small_gap,
            small_gap,
            63.208,
        ],
    }


def special_1500():
    # 26 packet: 25 packet 54 byte và một packet 150 byte.
    return {
        "sizes": [150] + [54] * 25,
        # Tổng khoảng 11 ms, max 5 ms.
        "gaps": (
            [0.005]
            + [0.001] * 6
            + [0.0] * 18
        ),
    }


def special_1676():
    # 26 packet, tổng=1676, max=150,
    # mean≈64.46, std≈26.38.
    return {
        "sizes": [
            150, 150, 95, 63, 57,
            56, 56, 56, 56, 56, 56,
            55, 55, 55, 55, 55,
            55, 55, 55, 55, 55,
            55, 55, 55, 55, 55,
        ],
        # Tổng 77.849 giây, max 39.586 giây.
        "gaps": [
            39.586,
            38.263,
        ] + [0.0] * 23,
    }


def special_1466():
    # 12 packet, tổng=1466, max=357.
    return {
        "sizes": [
            357, 306, 93, 83,
            80, 79,
            78, 78, 78, 78, 78, 78,
        ],
        # Tổng 12 ms, max 2 ms.
        "gaps": [
            0.002,
        ] + [0.001] * 10,
    }


def special_196(duration_ms):
    return {
        "sizes": [54, 54, 88],
        "gaps": (
            [0.001, 0.001]
            if duration_ms == 2
            else [0.0, 0.001]
        ),
    }


# Chuỗi 60 flow lấy theo một cửa sổ DATA EXFILTRATION
# mà model hiện tại nhận diện đúng ở cả flow 50 và flow 60.
PROFILES = [
    tiny_flow(44),
    tiny_flow(44),
    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(44),
    tiny_flow(44),

    special_1467(),
    special_1467(),

    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(44),
    tiny_flow(44),

    special_363(63266),
    special_363(63265),

    tiny_flow(45),
    tiny_flow(44),
    tiny_flow(42),
    tiny_flow(42),
    tiny_flow(60),
    tiny_flow(60),
    tiny_flow(58),
    tiny_flow(58),
    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(44),
    tiny_flow(44),

    special_1500(),
    special_1500(),

    special_1676(),
    special_1676(),

    special_1466(),
    special_1466(),

    tiny_flow(46),
    tiny_flow(45),
    tiny_flow(43),
    tiny_flow(43),

    special_196(2),
    special_196(1),

    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(43),
    tiny_flow(43),
    tiny_flow(45),
    tiny_flow(45),
    tiny_flow(43),
    tiny_flow(43),
    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(43),
    tiny_flow(43),
    tiny_flow(46),
    tiny_flow(46),
    tiny_flow(43),
    tiny_flow(43),
    tiny_flow(45),
    tiny_flow(44),
    tiny_flow(42),
    tiny_flow(42),
    tiny_flow(44),
    tiny_flow(44),
]


# Chỉ giữ 50 profile tạo nên cửa sổ đã được model
# nhận diện đúng là DATA EXFILTRATION.
PROFILES = PROFILES[:50]

if len(PROFILES) != 50:
    raise RuntimeError(
        f"Profile count phải là 50, hiện tại={len(PROFILES)}"
    )


def wait_until(target_time):
    while True:
        remaining = target_time - time.monotonic()

        if remaining <= 0:
            return

        if remaining > 0.01:
            time.sleep(remaining - 0.005)
        else:
            time.sleep(0.0005)


def create_packet(
    source_port,
    frame_size,
    sequence_number,
):
    # Ethernet + IPv4 + TCP không option = 54 byte.
    payload_size = frame_size - 54

    packet = (
        IP(
            src=SOURCE_IP,
            dst=DESTINATION_IP,
        )
        / TCP(
            sport=source_port,
            dport=DESTINATION_PORT,
            flags="A",
            seq=sequence_number,
            ack=1,
        )
    )

    if payload_size > 0:
        packet = packet / Raw(
            os.urandom(payload_size)
        )

    return packet, payload_size


def run_flow(flow_index, profile, global_start):
    source_port = 40000 + flow_index

    sizes = profile["sizes"]
    gaps = profile["gaps"]

    if len(gaps) != len(sizes) - 1:
        raise RuntimeError(
            f"Flow {flow_index}: số gap không hợp lệ"
        )

    expected_duration = sum(gaps)

    desired_end = (
        global_start
        + BASE_END_TIME
        + flow_index * END_SPACING
    )

    desired_start = (
        desired_end
        - expected_duration
    )

    # Mở raw socket trước khi đến thời điểm gửi.
    socket_l3 = conf.L3socket(
        iface=INTERFACE
    )

    try:
        wait_until(desired_start)

        actual_start = time.monotonic()
        sequence_number = 100000 + flow_index * 10000

        packet, payload_size = create_packet(
            source_port,
            sizes[0],
            sequence_number,
        )

        socket_l3.send(packet)
        sequence_number += payload_size

        scheduled_time = desired_start

        for gap, frame_size in zip(
            gaps,
            sizes[1:],
        ):
            scheduled_time += gap
            wait_until(scheduled_time)

            packet, payload_size = create_packet(
                source_port,
                frame_size,
                sequence_number,
            )

            socket_l3.send(packet)
            sequence_number += payload_size

        actual_duration = (
            time.monotonic()
            - actual_start
        )

        return {
            "flow": flow_index + 1,
            "source_port": source_port,
            "packets": len(sizes),
            "bytes": sum(sizes),
            "target_duration": expected_duration,
            "actual_duration": actual_duration,
        }

    finally:
        socket_l3.close()


print(
    "DATA EXFILTRATION v3",
    flush=True,
)

print(
    f"Source      : {SOURCE_IP}",
    flush=True,
)

print(
    f"Destination : "
    f"{DESTINATION_IP}:{DESTINATION_PORT}",
    flush=True,
)

print(
    f"Đang lập lịch {len(PROFILES)} flow. "
    "Kịch bản mất khoảng 95 giây.",
    flush=True,
)

global_start = time.monotonic()

with concurrent.futures.ThreadPoolExecutor(
    max_workers=len(PROFILES)
) as executor:

    futures = [
        executor.submit(
            run_flow,
            index,
            profile,
            global_start,
        )
        for index, profile in enumerate(PROFILES)
    ]

    results = []

    for future in concurrent.futures.as_completed(
        futures
    ):
        result = future.result()
        results.append(result)

        print(
            f"Flow {result['flow']:02d}: "
            f"sport={result['source_port']} "
            f"packets={result['packets']} "
            f"bytes={result['bytes']} "
            f"target={result['target_duration']:.3f}s "
            f"actual={result['actual_duration']:.3f}s",
            flush=True,
        )

results.sort(
    key=lambda item: item["flow"]
)

print(
    f"Completed flows: {len(results)}",
    flush=True,
)

print(
    "DATA EXFILTRATION v3 completed",
    flush=True,
)
