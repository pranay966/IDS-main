"""
feature_extractor.py — Convert captured packet summaries → 41-feature KDD vector
Compatible with rf_model, svm_model, ann_model (and extended to 64 for CNN).
"""

import math
from collections import Counter
import numpy as np

# KDD NSL feature columns (41 features, same order as model_utils.py)
FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]

# Protocol numeric encoding
PROTOCOL_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "OTHER": 0}

# Service port → numeric index (simplified KDD mapping)
SERVICE_PORT_MAP = {
    80: 1,    # http
    443: 2,   # https
    22: 3,    # ssh
    21: 4,    # ftp
    25: 5,    # smtp
    53: 6,    # dns
    23: 7,    # telnet
    110: 8,   # pop3
    143: 9,   # imap
    3306: 10, # mysql
    5432: 11, # postgres
    8080: 12, # http-alt
    3389: 13, # rdp
}

# TCP flag string → numeric (S=SYN, F=FIN, R=RST, P=PSH, A=ACK)
FLAG_MAP = {
    "S": 1,   # SYN
    "SA": 2,  # SYN-ACK
    "F": 3,   # FIN
    "FA": 4,  # FIN-ACK
    "R": 5,   # RST
    "RA": 6,  # RST-ACK
    "PA": 7,  # PSH-ACK (normal data)
    "A": 8,   # ACK
    "":  0,
}


def _encode_flags(flag_str: str) -> int:
    """Convert scapy flag string like 'S', 'PA', 'RA' → int."""
    cleaned = flag_str.strip().upper()
    # Remove numeric scapy suffixes e.g. 'S  0x002'
    cleaned = cleaned.split()[0] if cleaned else ""
    return FLAG_MAP.get(cleaned, 0)


def _encode_service(dst_port: int) -> int:
    return SERVICE_PORT_MAP.get(dst_port, 0)


def _detect_syn_flood(packets: list) -> float:
    """Fraction of packets that are pure SYN (potential flood)."""
    if not packets:
        return 0.0
    syn_count = sum(
        1 for p in packets
        if "S" in p.get("flags", "") and "A" not in p.get("flags", "")
    )
    return round(syn_count / len(packets), 4)


def _dst_host_stats(packets: list, target_ip: str) -> dict:
    """Compute dst_host_* features for a specific destination IP."""
    same_host = [p for p in packets if p.get("dst_ip") == target_ip]
    total = len(packets) or 1
    same = len(same_host) or 1

    services = [p.get("dst_port", 0) for p in same_host]
    srv_counts = Counter(services)
    most_common_srv = srv_counts.most_common(1)[0][0] if srv_counts else 0
    same_srv = sum(1 for s in services if s == most_common_srv)

    src_ports = [p.get("src_port", 0) for p in same_host]
    src_port_counts = Counter(src_ports)
    most_common_src = src_port_counts.most_common(1)[0][0] if src_port_counts else 0
    same_src_port = sum(1 for sp in src_ports if sp == most_common_src)

    unique_hosts = len(set(p.get("dst_ip") for p in same_host))

    return {
        "dst_host_count": min(len(same_host), 255),
        "dst_host_srv_count": min(same, 255),
        "dst_host_same_srv_rate": round(same_srv / (same or 1), 4),
        "dst_host_diff_srv_rate": round(1 - same_srv / (same or 1), 4),
        "dst_host_same_src_port_rate": round(same_src_port / (same or 1), 4),
        "dst_host_srv_diff_host_rate": round(unique_hosts / (same or 1), 4),
        "dst_host_serror_rate": _detect_syn_flood(same_host),
        "dst_host_srv_serror_rate": _detect_syn_flood(same_host),
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }


def packets_to_features(packets: list, n_features: int = 41) -> np.ndarray:
    """
    Convert a list of packet-summary dicts into a (1, n_features) numpy array
    representing aggregate traffic behaviour — ready for ML models.

    packets: list of dicts from packet_capture._summarise_packet()
    n_features: 41 for sklearn models, 64 for CNN (zero-padded)
    """
    if not packets:
        return np.zeros((1, n_features), dtype=float)

    total = len(packets)
    proto_counts = Counter(p.get("protocol", "OTHER") for p in packets)
    dominant_proto = proto_counts.most_common(1)[0][0]

    # Duration: elapsed time between first and last packet
    timestamps = [p["timestamp"] for p in packets if "timestamp" in p]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    # src/dst bytes aggregated
    total_src_bytes = sum(p.get("src_bytes", 0) for p in packets)
    total_dst_bytes = sum(p.get("dst_bytes", 0) for p in packets)

    # Flags
    flags_list = [p.get("flags", "") for p in packets]
    syn_count = sum(
        1 for f in flags_list
        if "S" in f.upper() and "A" not in f.upper()
    )
    rst_count = sum(1 for f in flags_list if "R" in f.upper())

    serror_rate = round(syn_count / total, 4)
    rerror_rate = round(rst_count / total, 4)

    # Service from dominant dst_port
    dst_ports = [p.get("dst_port", 0) for p in packets]
    dominant_port = Counter(dst_ports).most_common(1)[0][0] if dst_ports else 0
    service = _encode_service(dominant_port)

    # Dominant flags
    flags_encoded = _encode_flags(Counter(flags_list).most_common(1)[0][0]) if flags_list else 0

    # Count features (connections to same host in last 2 sec)
    recent = [p for p in packets if time_ago(p) < 2.0]
    count = len(recent) or total

    # land: any land attack packets
    land = int(any(p.get("land", 0) for p in packets))
    urgent = int(any(p.get("urgent", 0) for p in packets))

    # dst_host stats (use most common dst_ip)
    dst_ips = [p.get("dst_ip") for p in packets if p.get("dst_ip")]
    dominant_dst = Counter(dst_ips).most_common(1)[0][0] if dst_ips else ""
    dh = _dst_host_stats(packets, dominant_dst)

    vec = {
        "duration":               round(duration, 4),
        "protocol_type":          PROTOCOL_MAP.get(dominant_proto, 0),
        "service":                service,
        "flag":                   flags_encoded,
        "src_bytes":              total_src_bytes,
        "dst_bytes":              total_dst_bytes,
        "land":                   land,
        "wrong_fragment":         0,
        "urgent":                 urgent,
        "hot":                    0,
        "num_failed_logins":      0,
        "logged_in":              0,
        "num_compromised":        0,
        "root_shell":             0,
        "su_attempted":           0,
        "num_root":               0,
        "num_file_creations":     0,
        "num_shells":             0,
        "num_access_files":       0,
        "num_outbound_cmds":      0,
        "is_host_login":          0,
        "is_guest_login":         0,
        "count":                  min(count, 512),
        "srv_count":              min(total, 512),
        "serror_rate":            serror_rate,
        "srv_serror_rate":        serror_rate,
        "rerror_rate":            rerror_rate,
        "srv_rerror_rate":        rerror_rate,
        "same_srv_rate":          round(1 - len(set(dst_ports)) / (total or 1), 4),
        "diff_srv_rate":          round(len(set(dst_ports)) / (total or 1), 4),
        "srv_diff_host_rate":     round(len(set(dst_ips)) / (total or 1), 4),
        **dh,
    }

    arr = np.array([vec.get(col, 0.0) for col in FEATURE_COLUMNS], dtype=float)

    if n_features > 41:
        arr = np.concatenate([arr, np.zeros(n_features - 41)])

    return arr.reshape(1, -1)


def time_ago(pkt: dict) -> float:
    """Seconds since packet was captured."""
    ts = pkt.get("timestamp", 0)
    if ts == 0:
        return 9999.0
    return time.time() - ts


import time  # noqa: E402 (imported at bottom to avoid circular-ish issue with tests)
