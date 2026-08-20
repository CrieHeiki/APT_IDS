import concurrent.futures
import os
import socket
import ssl
import struct
import time

HOST = "192.168.56.20"
PORT = 8443

FLOW_COUNT = int(os.environ.get("FLOW_COUNT", "5"))
DURATION = 60.08

SCHEDULE = [
    (4.0, 1),
    (8.0, 345),
    (12.0, 1),
    (27.0, 1),
    (31.0, 230),
    (35.0, 1),
    (39.0, 1),
    (45.0, 1),
]


def make_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_TICKET
    context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    return context


def recv_exact(sock, length):
    result = bytearray()

    while len(result) < length:
        chunk = sock.recv(length - len(result))

        if not chunk:
            raise ConnectionError("Server disconnected")

        result.extend(chunk)

    return bytes(result)


def create_flow(flow_id):
    raw_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    raw_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_KEEPALIVE,
        1,
    )

    raw_socket.setsockopt(
        socket.IPPROTO_TCP,
        socket.TCP_KEEPIDLE,
        15,
    )

    raw_socket.setsockopt(
        socket.IPPROTO_TCP,
        socket.TCP_KEEPINTVL,
        15,
    )

    raw_socket.setsockopt(
        socket.IPPROTO_TCP,
        socket.TCP_KEEPCNT,
        4,
    )

    raw_socket.settimeout(10)
    raw_socket.connect((HOST, PORT))

    tls_socket = make_context().wrap_socket(
        raw_socket,
        server_hostname="lab-c2",
    )

    tls_socket.settimeout(5)
    started = time.monotonic()

    sent_payload = 0
    received_payload = 0

    try:
        for message_index, (scheduled_time, payload_size) in enumerate(
            SCHEDULE
        ):
            wait_time = (
                started
                + scheduled_time
                - time.monotonic()
            )

            if wait_time > 0:
                time.sleep(wait_time)

            payload = os.urandom(payload_size)

            tls_socket.sendall(
                struct.pack("!H", len(payload)) + payload
            )

            sent_payload += len(payload)

            if message_index == 1:
                header = recv_exact(tls_socket, 2)
                response_length = struct.unpack(
                    "!H",
                    header,
                )[0]

                response = recv_exact(
                    tls_socket,
                    response_length,
                )

                received_payload += len(response)

        remaining = (
            started
            + DURATION
            - time.monotonic()
        )

        if remaining > 0:
            time.sleep(remaining)

        elapsed = time.monotonic() - started

        tls_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )

        tls_socket.close()

        return (
            flow_id,
            elapsed,
            sent_payload,
            received_payload,
        )

    except Exception:
        try:
            tls_socket.close()
        except OSError:
            pass

        raise


print(f"Creating {FLOW_COUNT} calibrated TLS flows")

with concurrent.futures.ThreadPoolExecutor(
    max_workers=FLOW_COUNT
) as executor:

    futures = []

    for flow_id in range(1, FLOW_COUNT + 1):
        futures.append(
            executor.submit(create_flow, flow_id)
        )

        time.sleep(0.05)

    for future in concurrent.futures.as_completed(futures):
        (
            flow_id,
            elapsed,
            sent_payload,
            received_payload,
        ) = future.result()

        print(
            f"Flow {flow_id:02d}: "
            f"duration={elapsed:.3f}s "
            f"application_sent={sent_payload} "
            f"application_received={received_payload}"
        )

print("Foothold v5 completed")
