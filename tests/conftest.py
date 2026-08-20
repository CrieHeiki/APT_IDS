from __future__ import annotations

from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


def fake_cicflow_row() -> dict[str, str]:
    return {
        "Timestamp": "2024-01-01 00:00:00",
        "Src IP": "10.0.0.10",
        "Dst IP": "10.0.0.20",
        "Src Port": "4444",
        "Dst Port": "443",
        "Protocol": "6",
        "Flow Duration": "2000000",
        "Tot Fwd Pkts": "10",
        "Tot Bwd Pkts": "8",
        "TotLen Fwd Pkts": "1500",
        "TotLen Bwd Pkts": "2400",
        "Pkt Len Min": "40",
        "Pkt Len Mean": "216.7",
        "Pkt Len Std": "32.5",
        "Pkt Len Max": "800",
        "Fwd Pkt Len Min": "40",
        "Fwd Pkt Len Mean": "150",
        "Fwd Pkt Len Std": "20",
        "Fwd Pkt Len Max": "500",
        "Bwd Pkt Len Min": "40",
        "Bwd Pkt Len Mean": "300",
        "Bwd Pkt Len Std": "45",
        "Bwd Pkt Len Max": "900",
        "Flow IAT Min": "1000",
        "Flow IAT Mean": "10000",
        "Flow IAT Std": "2500",
        "Flow IAT Max": "50000",
        "Fwd IAT Tot": "1800000",
        "Fwd IAT Min": "1000",
        "Fwd IAT Mean": "9000",
        "Fwd IAT Std": "2000",
        "Fwd IAT Max": "40000",
        "Bwd IAT Tot": "1600000",
        "Bwd IAT Min": "1200",
        "Bwd IAT Mean": "11000",
        "Bwd IAT Std": "2600",
        "Bwd IAT Max": "52000",
        "FIN Flag Cnt": "0",
        "SYN Flag Cnt": "1",
        "RST Flag Cnt": "1",
        "PSH Flag Cnt": "2",
        "ACK Flag Cnt": "14",
        "URG Flag Cnt": "0",
        "CWE Flag Count": "0",
        "ECE Flag Cnt": "0",
        "Fwd SYN Flags": "1",
        "Fwd CWR Flags": "0",
        "Fwd ECE Flags": "0",
        "Fwd URG Flags": "0",
        "Fwd ACK Flags": "9",
        "Fwd PSH Flags": "1",
        "Fwd RST Flags": "1",
        "Fwd FIN Flags": "0",
        "Bwd SYN Flags": "0",
        "Bwd ACK Flags": "5",
        "Bwd PSH Flags": "1",
        "Bwd RST Flags": "0",
        "Bwd FIN Flags": "0",
    }


@pytest.fixture(scope="session")
def artifact_bundle():
    pytest.importorskip("joblib")
    pytest.importorskip("pandas")
    from app.preprocessing import ArtifactBundle

    return ArtifactBundle.load(ARTIFACTS_DIR)

