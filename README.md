# PQC-Aware Suricata Detection Rules

Open-source detection logic that lets Suricata (or any IDS working from the
same principles) correctly distinguish **legitimate PQC-hybrid TLS 1.3
traffic** from a **hybrid-downgrade attack** — instead of the naive
size-threshold heuristics used by today's tooling, which flag *all* PQC
traffic as anomalous.

Built as the empirical/tooling component of a research project on SOC
readiness for post-quantum cryptography migration.

## TL;DR Result

On realistic mixed classical + PQC-hybrid traffic, naive size-based IDS
heuristics produce a **50% false-positive rate**. Our correlation-based
ruleset produces **0%** false positives while still catching **100%** of
simulated downgrade attacks, for the semantically correct reason.

See [`RESULTS.md`](RESULTS.md) for full methodology, results tables, and
limitations.

## Project Structure

```
pqc-soc-research/
├── scripts/
│   ├── tls_crafter.py       # Byte-accurate TLS 1.3 ClientHello/ServerHello builder
│   ├── generate_pcaps.py    # Generates all test scenario pcaps + ground-truth manifests
│   └── run_experiments.py   # Runs the full ruleset x scenario test matrix
├── rules/
│   ├── legacy_naive.rules   # Baseline: today's naive size-threshold heuristic
│   └── pqc_aware.rules      # Proposed: client/server group-correlation logic
├── pcaps/                   # Generated test traffic (4 scenarios) + manifests
├── results/
│   └── raw_results.json     # Detailed per-scenario alert/ground-truth data
├── logs/                    # Raw Suricata eve.json output per scenario x ruleset
└── RESULTS.md               # Full write-up: methodology, results, limitations
```

## Quick Start

Requires Suricata (7.x) and Python 3 with `scapy`.

```bash
pip3 install scapy --break-system-packages

cd scripts
python3 generate_pcaps.py      # build test traffic
python3 run_experiments.py     # run the experiment matrix
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
group codepoints, Snort3 port, certificate-level detection) welcome.
