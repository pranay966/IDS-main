"""
app.py — Flask API server for IDS
Extended with real-time packet capture endpoints.
- /api/detect             — existing manual detection (unchanged)
- /api/capture/start      — start a live capture session
- /api/capture/stop       — stop the current session
- /api/capture/status     — session stats
- /api/capture/analyze    — run ML model on captured packets
- /api/capture/stream     — Server-Sent Events live stream
- /api/capture/interfaces — list available network interfaces
"""

import os
import json
import random
import time
import queue
from collections import Counter
import joblib
import torch
import torch.nn as nn
from torchvision import models
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS

from model_utils import parse_features, predict_sklearn, predict_cnn
import packet_capture as pc
from feature_extractor import packets_to_features

app = Flask(__name__)
CORS(app)

DIR = os.path.dirname(__file__)


# -----------------------------
# CNN ARCHITECTURE (Recreated)
# -----------------------------
class FineTunedCNN(nn.Module):
    def __init__(self, input_size=64, n_classes=5):
        super().__init__()
        self.base = models.resnet18(weights=None)
        self.base.conv1 = nn.Conv2d(1, 64, kernel_size=3, stride=1, padding=1, bias=False)

        in_feats = self.base.fc.in_features
        self.base.fc = nn.Sequential(
            nn.Linear(in_feats, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, n_classes)
        )

    def forward(self, x):
        x = x.unsqueeze(1).unsqueeze(-1)
        return self.base(x)


def _load(filename):
    path = os.path.join(DIR, filename)
    if not os.path.exists(path):
        print(f"[WARN] Not found: {filename}")
        return None
    try:
        obj = joblib.load(path)
        print(f"[OK] Loaded: {filename}")
        return obj
    except Exception as e:
        print(f"[ERROR] Error loading {filename}: {e}")
        return None


print("\n[INFO] Loading IDS models...")

ENCODER = _load("label_encoder.pkl")
PCA_TRANSFORMER = _load("pca_transformer.pkl")
rf_model = _load("rf_model.pkl")
svm_model = _load("svm_model.pkl")
ann_model = _load("ann_model.pkl")

# -------- Load CNN properly --------
cnn_model = None
cnn_weights_path = os.path.join(DIR, "cnn_model.pth")

if os.path.exists(cnn_weights_path) and ENCODER is not None:
    try:
        cnn_model = FineTunedCNN(
            input_size=64,
            n_classes=len(ENCODER.classes_)
        )
        weights = torch.load(cnn_weights_path, map_location="cpu")
        cnn_model.load_state_dict(weights)
        cnn_model.eval()
        print("[OK] CNN model initialized with weights")
    except Exception as e:
        print("[ERROR] CNN loading failed:", e)
        cnn_model = None


MODELS = {
    "rf":  {"obj": rf_model,  "type": "sklearn"},
    "svm": {"obj": svm_model, "type": "sklearn"},
    "ann": {"obj": ann_model, "type": "sklearn"},
    "cnn": {"obj": cnn_model, "type": "torch"},
}

print("[INFO] Server ready.\n")


def resolve_model_key(model_type: str) -> str:
    aliases = {"ml": "rf", "tl": "cnn"}
    return aliases.get(model_type.lower(), model_type.lower())


DEMO_CATS = ["DoS", "Probe", "R2L", "U2R"]
MALICIOUS_HINTS = [
    "attack", "dos", "probe", "exploit",
    "overflow", "scan", "flood",
    "malicious", "hack", "inject", "ddos"
]


def _demo(packet_data: str):
    kw = (packet_data or "").lower()
    if any(h in kw for h in MALICIOUS_HINTS):
        return {
            "prediction": "malicious",
            "confidence": round(random.uniform(0.75, 0.98), 4),
            "attackType": random.choice(DEMO_CATS)
        }
    return {
        "prediction": "safe",
        "confidence": round(random.uniform(0.82, 0.99), 4),
        "attackType": None
    }


# ============================================================
# EXISTING ENDPOINT — unchanged
# ============================================================
@app.route("/api/detect", methods=["POST"])
def detect():
    body = request.get_json(force=True, silent=True) or {}
    packet_data = body.get("packetData", "")
    model_type = body.get("modelType", "rf")
    features = body.get("features") or {}

    key = resolve_model_key(model_type)
    entry = MODELS.get(key)

    if not entry or entry["obj"] is None:
        return jsonify(_demo(packet_data))

    import re
    nums = re.findall(r"-?\d+\.?\d*", packet_data)
    if len(nums) == 0:
        return jsonify(_demo(packet_data))

    X = parse_features(packet_data, features, 64)
    if PCA_TRANSFORMER is not None:
        try:
            X = PCA_TRANSFORMER.transform(X)
        except Exception:
            # Keep raw features if transform fails
            pass

    try:
        if entry["type"] == "torch":
            result = predict_cnn(entry["obj"], ENCODER, X)
        else:
            result = predict_sklearn(entry["obj"], ENCODER, X)
    except Exception as exc:
        print("🔥 Prediction error:", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify(result)


# ============================================================
# CAPTURE ENDPOINTS
# ============================================================

# Shared state: one active session per server instance
_active_session: pc.CaptureSession | None = None


@app.route("/api/capture/interfaces", methods=["GET"])
def capture_interfaces():
    """Return available network interfaces."""
    ifaces = pc.get_interfaces()
    return jsonify({"interfaces": ifaces, "scapy_available": pc.SCAPY_AVAILABLE})


@app.route("/api/capture/start", methods=["POST"])
def capture_start():
    """Start a new packet capture session."""
    global _active_session

    # Stop any running session first
    if _active_session and _active_session.running:
        _active_session.stop()

    body = request.get_json(force=True, silent=True) or {}
    interface = body.get("interface") or None

    _active_session = pc.create_session(interface=interface)
    _active_session.start()

    if _active_session.error:
        return jsonify({"error": _active_session.error}), 500

    return jsonify({
        "session_id": _active_session.session_id,
        "status": "capturing",
        "message": "Packet capture started"
    })


@app.route("/api/capture/stop", methods=["POST"])
def capture_stop():
    """Stop the active capture session."""
    global _active_session
    if not _active_session:
        return jsonify({"error": "No active session"}), 404

    _active_session.stop()
    status = _active_session.status()
    return jsonify({**status, "message": "Capture stopped"})


@app.route("/api/capture/status", methods=["GET"])
def capture_status():
    """Get current session stats."""
    if not _active_session:
        return jsonify({
            "running": False,
            "packet_count": 0,
            "message": "No capture session active"
        })
    return jsonify(_active_session.status())


@app.route("/api/capture/simulate-attack", methods=["POST"])
def capture_simulate_attack():
    """Inject synthetic malicious-like packets into active session for testing."""
    global _active_session
    if not _active_session:
        return jsonify({"error": "No active session. Start capture first."}), 400

    body = request.get_json(force=True, silent=True) or {}
    attack_kind = str(body.get("kind", "port_scan")).lower()
    count = int(body.get("count", 80))
    count = max(10, min(count, 500))

    now = time.time()
    target_ip = body.get("targetIp") or "192.168.1.5"
    src_ip = body.get("srcIp") or "192.168.1.100"

    simulated_packets = []
    for i in range(count):
        if attack_kind == "syn_flood":
            dst_port = int(body.get("port", 4444))
            flags = "S"
        else:
            # Default: port_scan pattern across many ports
            dst_port = 1024 + (i % 400)
            flags = "S" if i % 3 != 0 else "RA"

        pkt = {
            "timestamp": now - (count - i) * 0.02,
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "length": 96,
            "src_bytes": 96,
            "dst_bytes": 0,
            "flags": flags,
            "src_port": 50000 + (i % 1000),
            "dst_port": dst_port,
            "dns_query": None,
            "duration": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
        }
        simulated_packets.append(pkt)
        _active_session.packets.append(pkt)
        _active_session._broadcast({"type": "packet", "data": pkt})

    return jsonify({
        "status": "ok",
        "message": "Simulated attack packets injected",
        "attackKind": attack_kind,
        "injectedCount": len(simulated_packets),
        "targetIp": target_ip,
    })


@app.route("/api/capture/analyze", methods=["POST"])
def capture_analyze():
    """Run an ensemble ML decision on the latest captured traffic window."""
    global _active_session

    if not _active_session:
        return jsonify({"error": "No capture session. Start capture first."}), 400

    body = request.get_json(force=True, silent=True) or {}
    # Frontend may pass the selected model, but the final decision uses an ensemble rule
    _ = body.get("modelType", "rf")

    packets = list(_active_session.packets)
    if not packets:
        return jsonify({"error": "No packets captured yet."}), 400

    # ------------------------------------------------------------
    # 1) Rolling window (prevents “fixed / stale” predictions)
    # ------------------------------------------------------------
    WINDOW_SECONDS = 25.0
    now = time.time()
    window_packets = [p for p in packets if (now - float(p.get("timestamp", now))) <= WINDOW_SECONDS]
    if not window_packets:
        # fallback: use the most recent portion
        window_packets = packets[-100:]

    # ------------------------------------------------------------
    # 2) Rule-Based Filtering (safe vs suspicious)
    # ------------------------------------------------------------
    # Keep these aligned with real benign traffic you see during browsing.
    SAFE_TCP_UDP_PORTS = (80, 443, 53)  # HTTP/HTTPS/DNS
    # Common benign service discovery / multicast traffic (often present in normal browsing).
    SAFE_UDP_PORTS = (123, 137, 138, 1900, 5353, 67, 68)  # NTP, NetBIOS, SSDP, mDNS, DHCP

    def _is_multicast_ipv4(ip: str | None) -> bool:
        if not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
        except ValueError:
            return False
        return 224 <= first <= 239  # 224.0.0.0/4

    def _is_link_local_ipv4(ip: str | None) -> bool:
        return bool(ip and ip.startswith("169.254."))

    safe_packets = []
    suspicious_packets = []
    for p in window_packets:
        sport = p.get("src_port", 0) or 0
        dport = p.get("dst_port", 0) or 0
        dst_ip = p.get("dst_ip")
        proto = p.get("protocol", "")

        # 2a) Hard-safe ports for typical browsing paths.
        if sport in SAFE_TCP_UDP_PORTS or dport in SAFE_TCP_UDP_PORTS:
            safe_packets.append(p)
            continue

        # 2b) Hard-safe multicast / link-local destinations.
        if _is_multicast_ipv4(dst_ip) or _is_link_local_ipv4(dst_ip):
            safe_packets.append(p)
            continue

        # 2c) Hard-safe benign UDP services.
        if proto == "UDP" and (sport in SAFE_UDP_PORTS or dport in SAFE_UDP_PORTS):
            safe_packets.append(p)
            continue

        # Otherwise, treat as suspicious and evaluate with ML.
        suspicious_packets.append(p)

    normal_count = len(safe_packets)
    suspicious_count = len(suspicious_packets)
    total_count = len(window_packets)

    proto_counts = dict(Counter(p.get("protocol", "OTHER") for p in window_packets))

    # ------------------------------------------------------------
    # 3) Build “threat targets” list (IP + optional DNS domain)
    # ------------------------------------------------------------
    def _top_counter(values, k=5):
        c = Counter(v for v in values if v not in (None, "", "—"))
        return [{"value": val, "count": cnt} for val, cnt in c.most_common(k)]

    top_dst_ips = _top_counter([p.get("dst_ip") for p in suspicious_packets], 5)
    top_src_ips = _top_counter([p.get("src_ip") for p in suspicious_packets], 5)
    top_dst_ports = _top_counter([p.get("dst_port") for p in suspicious_packets], 5)

    dst_ip_ports = []
    for p in suspicious_packets:
        if p.get("dst_ip") and p.get("dst_port"):
            dst_ip_ports.append(f"{p.get('dst_ip')}:{p.get('dst_port')}")
    top_dst_ip_ports = [{"value": val, "count": cnt} for val, cnt in Counter(dst_ip_ports).most_common(5)]

    top_domains = _top_counter([p.get("dns_query") for p in window_packets], 5)

    threatTargets = {
        "topDstIps": top_dst_ips,
        "topSrcIps": top_src_ips,
        "topDstPorts": top_dst_ports,
        "topDstIpPorts": top_dst_ip_ports,
        "topDomains": top_domains,
    }

    # ------------------------------------------------------------
    # 4) If no suspicious evidence, return a SAFE result (dynamic confidence)
    # ------------------------------------------------------------
    result = {
        "prediction": "safe",
        "confidence": 0.5,
        "attackType": None,
        "packetCount": total_count,
        "normalCount": normal_count,
        "suspiciousCount": suspicious_count,
        "maliciousCount": 0,
        "sessionId": _active_session.session_id,
        "protocolCounts": proto_counts,
        "perModel": {},
        "threatTargets": threatTargets,
        "decisionRule": "safe:no_suspicious_packets_in_window",
    }

    # IMPORTANT: If the real-time DPI engine caught a malicious URL during this capture session,
    # override the ML output since ML (flow-based) cannot read URL content.
    if hasattr(_active_session, 'url_threat_info') and _active_session.url_threat_info:
        ti = _active_session.url_threat_info
        result["prediction"] = "malicious"
        result["confidence"] = 0.99
        result["attackType"] = f"Malicious URL Output ({ti.get('keyword')})"
        result["maliciousCount"] = suspicious_count or 1
        result["decisionRule"] = "malicious:dpi_url_flagged"
        
        # Add the malicious domain strictly to top domains if not present
        domain = ti.get("domain", "")
        if domain and not any(d["value"] == domain for d in threatTargets["topDomains"]):
            threatTargets["topDomains"].insert(0, {"value": domain, "count": 1})
            
        return jsonify(result)

    if suspicious_count == 0:
        # Confidence rises with amount of normal traffic in window
        confidence = 0.6 + 0.35 * min(1.0, normal_count / 50.0)
        result["confidence"] = round(float(confidence), 4)
        return jsonify(result)

    # ------------------------------------------------------------
    # 4b) Evidence gate + heuristic attack detector
    # ------------------------------------------------------------
    # First detect clear malicious behavior using traffic patterns. This helps
    # catch local nmap scans even when a model disagrees.
    total_tcp = sum(1 for p in suspicious_packets if p.get("protocol") == "TCP")
    syn_like = 0
    for p in suspicious_packets:
        if p.get("protocol") != "TCP":
            continue
        flags = str(p.get("flags", "")).upper()
        if "S" in flags and "A" not in flags:
            syn_like += 1

    tcp_syn_ratio = float(syn_like) / float(total_tcp or 1)
    distinct_dst_ports = len(set(p.get("dst_port", 0) for p in suspicious_packets if p.get("dst_port")))
    distinct_dst_ips = len(set(p.get("dst_ip") for p in suspicious_packets if p.get("dst_ip")))
    suspicious_ratio = float(suspicious_count) / float(total_count or 1)

    # Heuristic attack signatures (priority before model voting)
    likely_port_scan = (
        suspicious_count >= 10
        and (
            distinct_dst_ports >= 8
            or (distinct_dst_ports >= 6 and tcp_syn_ratio >= 0.25)
        )
    )

    likely_syn_flood = (
        suspicious_count >= 20
        and total_tcp >= 15
        and tcp_syn_ratio >= 0.55
    )

    likely_multi_host_scan = (
        suspicious_count >= 30
        and distinct_dst_ips >= 5
        and distinct_dst_ports >= 10
    )

    heuristic_forced_malicious = likely_port_scan or likely_syn_flood or likely_multi_host_scan
    heuristic_attack_type = None
    heuristic_conf = 0.0
    if heuristic_forced_malicious:
        heuristic_attack_type = "Port Scan (Heuristic)"
        if likely_syn_flood:
            heuristic_attack_type = "DoS/SYN Flood (Heuristic)"
        elif likely_multi_host_scan:
            heuristic_attack_type = "Multi-Host Scan (Heuristic)"

        heuristic_conf = min(
            0.98,
            0.55
            + 0.2 * min(1.0, distinct_dst_ports / 30.0)
            + 0.15 * min(1.0, tcp_syn_ratio / 0.7)
            + 0.1 * min(1.0, suspicious_count / 90.0),
        )

    # Consider evidence "strong" only when indicators align.
    evidence_strong = (
        (tcp_syn_ratio >= 0.2 and suspicious_count >= 15)
        or (distinct_dst_ports >= 10 and suspicious_count >= 15)
        or (suspicious_ratio >= 0.35 and suspicious_count >= 25)
    )

    if not evidence_strong:
        # Treat as SAFE unless we have strong evidence.
        confidence = 0.6 + 0.25 * min(1.0, (1.0 - suspicious_ratio))
        result.update({
            "prediction": "safe",
            "confidence": round(float(confidence), 4),
            "attackType": None,
            "maliciousCount": 0,
            "perModel": {},
            "decisionRule": "rule:evidence_not_strong_enough",
        })
        return jsonify(result)

    # ------------------------------------------------------------
    # 5) Feature extraction (match models: 64-dim -> PCA -> models)
    # ------------------------------------------------------------
    X_raw = packets_to_features(suspicious_packets, n_features=64)
    X = X_raw
    if PCA_TRANSFORMER is not None:
        try:
            X = PCA_TRANSFORMER.transform(X_raw)
        except Exception:
            # If PCA transform fails, fall back to raw features.
            X = X_raw

    # ------------------------------------------------------------
    # 6) Run ensemble across all available models
    # ------------------------------------------------------------
    per_model = {}
    model_order = [("rf", rf_model), ("svm", svm_model), ("ann", ann_model), ("tl", cnn_model)]
    for model_name, model_obj in model_order:
        if model_obj is None:
            continue
        try:
            if model_name == "tl":
                per_model[model_name] = predict_cnn(model_obj, ENCODER, X)
            else:
                per_model[model_name] = predict_sklearn(model_obj, ENCODER, X)
        except Exception as exc:
            print(f"🔥 Model {model_name} prediction error:", exc)

    if not per_model:
        # Fallback to heuristics if all models are missing
        syn_rate = sum(
            1 for p in suspicious_packets
            if "S" in str(p.get("flags", "")) and "A" not in str(p.get("flags", ""))
        ) / float(suspicious_count)

        if syn_rate > 0.5:
            result.update({
                "prediction": "malicious",
                "confidence": round(0.65 + syn_rate * 0.25, 4),
                "attackType": "DoS (SYN Flood - Heuristic)",
                "maliciousCount": suspicious_count,
                "decisionRule": "heuristic:syndata_syn_rate_gt_0.5",
            })
        else:
            result.update({
                "confidence": round(0.55 + syn_rate * 0.25, 4),
                "decisionRule": "heuristic:syndata_syn_rate_le_0.5",
            })

        return jsonify(result)

    result["perModel"] = per_model

    available_model_names = list(per_model.keys())
    malicious_models = [k for k, v in per_model.items() if v.get("prediction") == "malicious"]
    safe_models = [k for k, v in per_model.items() if v.get("prediction") == "safe"]

    tl_res = per_model.get("tl")
    tl_conf = float(tl_res.get("confidence", 0.0)) if tl_res else 0.0

    # ------------------------------------------------------------
    # 7) Decision rule (conservative; reduces false positives)
    # ------------------------------------------------------------
    tl_high = tl_res and tl_res.get("prediction") == "malicious" and tl_conf >= 0.8

    malicious_all = (
        len(malicious_models) == len(available_model_names)
        and len(available_model_names) >= 2
    )

    malicious_majority = len(malicious_models) >= 3

    if heuristic_forced_malicious:
        final_pred = "malicious"
        rule = "heuristic+ensemble:attack_pattern_detected"
    elif malicious_all or malicious_majority or tl_high:
        final_pred = "malicious"
        rule = "ensemble:strong_agreement_or_tl_high"
    else:
        final_pred = "safe"
        rule = "ensemble:not_strong_enough"

    # Dynamic confidence: use evidence + average confidence over malicious models.
    evidence_weight = min(
        1.0,
        0.25
        + 0.35 * min(1.0, tcp_syn_ratio / 0.5)
        + 0.25 * min(1.0, distinct_dst_ports / 20.0)
        + 0.15 * min(1.0, suspicious_ratio / 0.6),
    )

    if final_pred == "malicious":
        mal_confs = [
            float(v.get("confidence", 0.0))
            for v in per_model.values()
            if v.get("prediction") == "malicious"
        ]
        avg_mal_conf = sum(mal_confs) / float(len(mal_confs) or 1)
        mal_items = [(k, v) for k, v in per_model.items() if v.get("prediction") == "malicious"]
        best_mal = (
            max(mal_items, key=lambda kv: float(kv[1].get("confidence", 0.0)))[1]
            if mal_items else {"attackType": heuristic_attack_type, "confidence": heuristic_conf}
        )
        model_conf = evidence_weight * avg_mal_conf if mal_confs else 0.0
        conf_out = max(model_conf, heuristic_conf) if heuristic_forced_malicious else model_conf
        conf_out = min(0.99, conf_out)
        result.update({
            "prediction": "malicious",
            "confidence": round(float(conf_out), 4),
            "attackType": best_mal.get("attackType") or heuristic_attack_type or "MALICIOUS",
            "maliciousCount": suspicious_count,
            "decisionRule": rule,
        })
    else:
        safe_confs = [
            float(v.get("confidence", 0.0))
            for v in per_model.values()
            if v.get("prediction") == "safe"
        ]
        avg_safe_conf = sum(safe_confs) / float(len(safe_confs) or 1)
        conf_out = max(0.5, min(0.99, evidence_weight * avg_safe_conf + 0.2))
        result.update({
            "prediction": "safe",
            "confidence": round(float(conf_out), 4),
            "attackType": None,
            "maliciousCount": 0,
            "decisionRule": rule,
        })

    return jsonify(result)


@app.route("/api/capture/stream", methods=["GET"])
def capture_stream():
    """Server-Sent Events stream — delivers packet events in real time."""
    global _active_session

    if not _active_session:
        def no_session():
            yield "data: {\"error\": \"No active session\"}\n\n"
        return Response(
            stream_with_context(no_session()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )

    sess = _active_session
    sub_queue = sess.subscribe()

    def event_generator():
        try:
            # Send a "connected" event immediately
            yield f"data: {json.dumps({'type': 'connected', 'session_id': sess.session_id})}\n\n"

            while True:
                try:
                    msg = sub_queue.get(timeout=1.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                    if msg.get("type") == "stopped":
                        break
                except queue.Empty:
                    # Heartbeat keep-alive comment
                    yield ": heartbeat\n\n"
        finally:
            sess.unsubscribe(sub_queue)

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "models_loaded": {k: v["obj"] is not None for k, v in MODELS.items()},
        "scapy_available": pc.SCAPY_AVAILABLE
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)