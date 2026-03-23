import sys
print("Python executable:", sys.executable)
print("Python version:", sys.version)

try:
    import scapy
    print("scapy version:", scapy.__version__)
    from scapy.all import conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    print("SCAPY_AVAILABLE: True")
    try:
        from scapy.arch.windows import L3RawSocket
        print("L3RawSocket: available")
    except Exception as e:
        print("L3RawSocket: NOT available —", e)
except ImportError as e:
    print("SCAPY_AVAILABLE: False — ImportError:", e)
