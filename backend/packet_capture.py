"""
packet_capture.py — Live packet sniffer using scapy (Windows/Npcap)
Manages capture sessions keyed by session_id.
"""

import threading
import time
import uuid
from collections import deque
from typing import Optional

# Lazy-import scapy so app.py can still start even if Npcap isn't installed
try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Packet summary structure (what we keep in RAM per packet)
# ---------------------------------------------------------------------------
def _summarise_packet(pkt) -> Optional[dict]:
    """Convert a scapy packet into a lightweight dict."""
    if not SCAPY_AVAILABLE:
        return None

    summary = {
        "timestamp": time.time(),
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "length": len(pkt),
        "src_bytes": len(pkt),
        "dst_bytes": 0,
        "flags": "",
        "src_port": 0,
        "dst_port": 0,
        "dns_query": None,
        "duration": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
    }

    # Handle IP or IPv6 layer
    if IP in pkt:
        summary["src_ip"] = pkt[IP].src
        summary["dst_ip"] = pkt[IP].dst
        summary["src_bytes"] = pkt[IP].len if pkt[IP].len else len(pkt)
    elif IPv6 in pkt:
        summary["src_ip"] = pkt[IPv6].src
        summary["dst_ip"] = pkt[IPv6].dst
        summary["src_bytes"] = pkt[IPv6].plen if pkt[IPv6].plen else len(pkt)

    if summary["src_ip"] is not None:
        if TCP in pkt:
            summary["protocol"] = "TCP"
            summary["src_port"] = pkt[TCP].sport
            summary["dst_port"] = pkt[TCP].dport
            summary["flags"] = str(pkt[TCP].flags)
            summary["urgent"] = pkt[TCP].urgptr
            if summary["src_ip"] == summary["dst_ip"] and summary["src_port"] == summary["dst_port"]:
                summary["land"] = 1

        elif UDP in pkt:
            summary["protocol"] = "UDP"
            summary["src_port"] = pkt[UDP].sport
            summary["dst_port"] = pkt[UDP].dport

            # Extract DNS query name (useful for “malicious URL/domain” UI)
            if pkt.haslayer(DNSQR) and DNSQR in pkt:
                try:
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", "ignore")
                    summary["dns_query"] = str(qname).strip().rstrip(".") or None
                except Exception:
                    summary["dns_query"] = None

        elif ICMP in pkt or ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
            summary["protocol"] = "ICMP"
            
    return summary


# ---------------------------------------------------------------------------
# CaptureSession — one logical sniff session
# ---------------------------------------------------------------------------
class CaptureSession:
    MAX_PACKETS = 500  # keep last N packets in memory

    def __init__(self, interface: Optional[str] = None):
        self.session_id = str(uuid.uuid4())
        self.interface = interface  # None → scapy picks default
        self.packets: deque = deque(maxlen=self.MAX_PACKETS)
        self.running = False
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self.error: Optional[str] = None

        # SSE subscribers: list of queue.Queue objects
        self._subscribers: list = []
        self._sub_lock = threading.Lock()

    # ------------------------------------------------------------------
    def start(self):
        if self.running:
            return
        if not SCAPY_AVAILABLE:
            self.error = (
                "scapy is not installed. "
                "Run: pip install scapy  and install Npcap from https://npcap.com/"
            )
            return
        self._stop_evt.clear()
        self.running = True
        self.start_time = time.time()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        self.running = False
        self.stop_time = time.time()
        # notify SSE subscribers that stream is done
        self._broadcast({"type": "stopped"})

    # ------------------------------------------------------------------
    def _sniff_loop(self):
        try:
            iface_kwargs = {}
            if self.interface:
                iface_kwargs["iface"] = self.interface

            sniff(
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_evt.is_set(),
                **iface_kwargs,
            )
        except Exception as exc:
            self.error = str(exc)
            self.running = False

    def _handle_packet(self, pkt):
        summary = _summarise_packet(pkt)
        if summary:
            self.packets.append(summary)
            self._broadcast({"type": "packet", "data": summary})

    # ------------------------------------------------------------------
    # SSE pub/sub helpers
    # ------------------------------------------------------------------
    def subscribe(self):
        """Return a queue that will receive broadcast dictionaries."""
        import queue
        q = queue.Queue(maxsize=200)
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def _broadcast(self, msg: dict):
        with self._sub_lock:
            for q in list(self._subscribers):
                try:
                    q.put_nowait(msg)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    def status(self) -> dict:
        elapsed = 0.0
        if self.start_time:
            end = self.stop_time or time.time()
            elapsed = round(end - self.start_time, 1)

        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        for p in self.packets:
            proto = p.get("protocol", "OTHER")
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

        return {
            "session_id": self.session_id,
            "running": self.running,
            "packet_count": len(self.packets),
            "elapsed_seconds": elapsed,
            "interface": self.interface or "default",
            "protocol_counts": proto_counts,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Session registry
# ---------------------------------------------------------------------------
_sessions: dict[str, CaptureSession] = {}
_registry_lock = threading.Lock()


def create_session(interface: Optional[str] = None) -> CaptureSession:
    sess = CaptureSession(interface=interface)
    with _registry_lock:
        _sessions[sess.session_id] = sess
    return sess


def get_session(session_id: str) -> Optional[CaptureSession]:
    return _sessions.get(session_id)


def active_sessions() -> list[CaptureSession]:
    return [s for s in _sessions.values() if s.running]


def get_interfaces() -> list[dict]:
    """Return list of available network interfaces with friendly names."""
    if not SCAPY_AVAILABLE:
        return []
    try:
        import platform
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            interfaces = []
            for iface in get_windows_if_list():
                label = iface.get("name") or iface.get("description") or iface.get("guid") or "Unknown"
                # For Windows sniff(), using the 'name' or 'description' or 'guid' works, Scapy resolves it
                interfaces.append({
                    "id": iface.get("name"),   # we'll use the friendly name as ID
                    "label": f"{label} ({iface.get('ipv4_metric', 0)})" if label != iface.get("name") else label,
                    "guid": iface.get("guid")
                })
            # Filter duplicates and remove loopbacks if we want, or keep them.
            return interfaces
        else:
            return [{"id": ifc, "label": ifc} for ifc in get_if_list()]
    except Exception as e:
        print("[packet_capture] Interface discovery error:", e)
        return [{"id": ifc, "label": ifc} for ifc in get_if_list()]
