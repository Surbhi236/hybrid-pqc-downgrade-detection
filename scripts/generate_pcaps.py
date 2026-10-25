"""
generate_pcaps.py
------------------
Generates four pcap scenarios used to evaluate Suricata detection logic:

  A. classical_baseline.pcap     - N normal classical-only TLS1.3 handshakes
  B. pqc_hybrid_legit.pcap       - N legitimate PQC-hybrid TLS1.3 handshakes
  C. pqc_downgrade_attack.pcap   - N handshakes where client offers hybrid PQC
                                    groups but ServerHello selects a classical
                                    group only (simulated on-path downgrade)
  D. mixed_traffic.pcap          - shuffled combination of A + B (realistic
                                    background traffic a SOC would see during
                                    a hybrid-migration period)

Each pcap also gets a matching manifest (.json) that records ground truth
labels per-flow (5-tuple + expected classification), so precision/recall can
be computed after running Suricata.
"""

import json
import random
from pathlib import Path
from scapy.all import wrpcap

from tls_crafter import (
    build_client_hello,
    build_server_hello,
    build_change_cipher_spec,
    build_placeholder_encrypted_record,
    make_tcp_stream,
    next_port,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_X25519_MLKEM768,
    GROUP_X25519_KYBER768_LEGACY,
    CS_AES_128_GCM_SHA256,
)

OUT_DIR = Path(__file__).resolve().parent.parent / "pcaps"
OUT_DIR.mkdir(exist_ok=True)

random.seed(42)  # reproducibility

SERVER_IP_POOL = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
CLIENT_IP_POOL = [f"192.168.1.{i}" for i in range(10, 60)]


def gen_classical_flow():
    client_ip = random.choice(CLIENT_IP_POOL)
    server_ip = random.choice(SERVER_IP_POOL)
    sport = next_port()
    dport = 443

    ch = build_client_hello(groups_offered=[GROUP_X25519, GROUP_SECP256R1])
    sh = build_server_hello(chosen_group=GROUP_X25519)

    pkts = make_tcp_stream(client_ip, server_ip, sport, dport, [ch], [sh])
    label = {
        "flow": f"{client_ip}:{sport}->{server_ip}:{dport}",
        "class": "classical",
        "expected_alert": False,
        "client_hello_len": len(ch),
        "server_hello_len": len(sh),
    }
    return pkts, label


def gen_pqc_hybrid_legit_flow():
    client_ip = random.choice(CLIENT_IP_POOL)
    server_ip = random.choice(SERVER_IP_POOL)
    sport = next_port()
    dport = 443

    # Client offers both classical and hybrid groups (normal hybrid negotiation)
    ch = build_client_hello(groups_offered=[GROUP_X25519, GROUP_X25519_MLKEM768])
    # Server picks the hybrid group -> genuine PQC-protected session
    sh = build_server_hello(chosen_group=GROUP_X25519_MLKEM768)

    pkts = make_tcp_stream(client_ip, server_ip, sport, dport, [ch], [sh])
    label = {
        "flow": f"{client_ip}:{sport}->{server_ip}:{dport}",
        "class": "pqc_hybrid_legit",
        "expected_alert": False,   # legit hybrid traffic should NOT be flagged
        "client_hello_len": len(ch),
        "server_hello_len": len(sh),
    }
    return pkts, label


def gen_downgrade_attack_flow():
    client_ip = random.choice(CLIENT_IP_POOL)
    server_ip = random.choice(SERVER_IP_POOL)
    sport = next_port()
    dport = 443

    # Client CAPABLE of + offering hybrid PQC group...
    ch = build_client_hello(groups_offered=[GROUP_X25519, GROUP_X25519_MLKEM768])
    # ...but negotiated ServerHello silently drops to classical-only group
    # (on-path attacker strips/forces classical group -> downgrade attack)
    sh = build_server_hello(chosen_group=GROUP_X25519)

    pkts = make_tcp_stream(client_ip, server_ip, sport, dport, [ch], [sh])
    label = {
        "flow": f"{client_ip}:{sport}->{server_ip}:{dport}",
        "class": "pqc_downgrade_attack",
        "expected_alert": True,   # this SHOULD be flagged
        "client_hello_len": len(ch),
        "server_hello_len": len(sh),
    }
    return pkts, label


def build_scenario(n, generator_fn, name):
    all_pkts = []
    manifest = []
    for _ in range(n):
        pkts, label = generator_fn()
        all_pkts.extend(pkts)
        manifest.append(label)
    pcap_path = OUT_DIR / f"{name}.pcap"
    wrpcap(str(pcap_path), all_pkts)
    with open(OUT_DIR / f"{name}_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] {name}: {n} flows, {len(all_pkts)} packets -> {pcap_path}")
    return manifest


def main():
    m_classical = build_scenario(200, gen_classical_flow, "classical_baseline")
    m_hybrid = build_scenario(200, gen_pqc_hybrid_legit_flow, "pqc_hybrid_legit")
    m_downgrade = build_scenario(100, gen_downgrade_attack_flow, "pqc_downgrade_attack")

    # Mixed traffic: shuffle classical + hybrid flows together (no attack)
    # to simulate realistic hybrid-migration background traffic.
    mixed_pkts = []
    mixed_manifest = []
    combo = [("classical", gen_classical_flow) for _ in range(100)] + \
            [("hybrid", gen_pqc_hybrid_legit_flow) for _ in range(100)]
    random.shuffle(combo)
    for _, fn in combo:
        pkts, label = fn()
        mixed_pkts.extend(pkts)
        mixed_manifest.append(label)
    wrpcap(str(OUT_DIR / "mixed_traffic.pcap"), mixed_pkts)
    with open(OUT_DIR / "mixed_traffic_manifest.json", "w") as f:
        json.dump(mixed_manifest, f, indent=2)
    print(f"[+] mixed_traffic: {len(combo)} flows, {len(mixed_pkts)} packets")


if __name__ == "__main__":
    main()
