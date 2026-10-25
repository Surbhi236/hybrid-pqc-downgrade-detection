# PQC-Aware Detection Rules for Suricata and Snort3

Open-source detection logic that lets Suricata and Snort3 (or any IDS working
from the same principles) correctly distinguish **legitimate PQC-hybrid TLS 1.3
traffic** from a **hybrid-downgrade attack** — instead of the naive
size-threshold heuristics used by today's tooling, which flag *all* PQC
traffic as anomalous.

Built as the empirical/tooling component of a research project on SOC
readiness for post-quantum cryptography migration.

## TL;DR Result

On realistic mixed classical + PQC-hybrid traffic, naive size-based IDS
heuristics produce a **50% false-positive rate**. Our correlation-based
ruleset produces **0%** false positives while still catching **100%** of
simulated downgrade attacks, for the semantically correct reason. Results are
identical on Suricata 7.0.3 and Snort3 3.12.2.0 (700 synthetic flows).

See [`RESULTS.md`](RESULTS.md) for full methodology, results tables, and
limitations.

## Project Structure

```
hybrid-pqc-downgrade-detection/
├── scripts/
│   ├── tls_crafter.py             # Byte-accurate TLS 1.3 ClientHello/ServerHello builder
│   ├── generate_pcaps.py          # Generates all test scenario pcaps + ground-truth manifests
│   ├── run_experiments.py         # Suricata: full ruleset x scenario test matrix
│   └── run_experiments_snort3.py  # Snort3: same matrix, same pcaps and manifests
├── rules/
│   ├── legacy_naive.rules         # Baseline: naive size-threshold heuristic
│   ├── pqc_aware.rules           # Proposed: client/server group-correlation (Suricata)
│   └── pqc_aware_snort3.rules    # Same logic, Snort3 syntax
├── pcaps/                         # Generated test traffic (4 scenarios) + manifests
├── results/
│   ├── raw_results.json           # Suricata per-scenario results
│   └── snort3_results.json        # Snort3 per-scenario results
└── RESULTS.md                     # Full write-up: methodology, results, limitations
```

## Quick Start

Requires Python 3 with `scapy`, plus Suricata (tested 7.0.3) and/or Snort3
(tested 3.12.2.0, built with libdaq >= 3.0.27).

```bash
pip3 install scapy --break-system-packages

cd scripts
python3 generate_pcaps.py      # build test traffic
python3 run_experiments.py           # Suricata experiment matrix
python3 run_experiments_snort3.py    # Snort3 experiment matrix
```

To test the ruleset manually against any pcap:

```bash
suricata -c /etc/suricata/suricata.yaml \
         -r pcaps/pqc_downgrade_attack.pcap \
         -S rules/pqc_aware.rules \
         -l /tmp/out --runmode=single
cat /tmp/out/eve.json | python3 -m json.tool
```

## Detection Logic Summary

| Signal | Meaning | Action |
|---|---|---|
| ClientHello offers hybrid PQC group (`X25519MLKEM768` / `X25519Kyber768`) | Client is PQC-capable | Silently tag flow, no alert |
| ServerHello negotiates hybrid group | Legitimate PQC-protected session | Silently tag flow, no alert |
| ClientHello offered hybrid **but** ServerHello negotiated classical-only | **Hybrid-downgrade attack** | **ALERT** (priority 1) |
| Oversized ClientHello matching no known group codepoint | Possibly proprietary/non-standard KEM | Flag for analyst triage (priority 3) |

## License / Use

Released for open research and SOC tooling use. Contributions (additional
group codepoints, certificate-level detection) welcome.
