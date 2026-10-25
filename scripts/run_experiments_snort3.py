"""
run_experiments_snort3.py
--------------------------
Snort3 equivalent of run_experiments.py. Runs the same pcap scenarios against
Snort3 (using pqc_aware_snort3.rules, the syntax-adapted port of
pqc_aware.rules) and legacy_naive.rules (unchanged - its syntax is already
Snort3-compatible), matching alerts back to ground-truth manifests exactly as
the Suricata runner does, so the two engines' results are directly comparable.
"""

import json
import re
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE / "pcaps"
RULES_DIR = BASE / "rules"
SNORT_BIN = "/usr/local/snort3/bin/snort"
SNORT_CONF = "/usr/local/snort3/etc/snort/snort.lua"

SCENARIOS = ["classical_baseline", "pqc_hybrid_legit", "pqc_downgrade_attack", "mixed_traffic"]
RULESETS = {
    "legacy_naive": RULES_DIR / "legacy_naive.rules",
    "pqc_aware": RULES_DIR / "pqc_aware_snort3.rules",
}

ALERT_LINE_RE = re.compile(
    r'\{TCP\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)'
)


def run_snort3(pcap_path: Path, ruleset_path: Path):
    env_cmd = [
        SNORT_BIN, "-c", SNORT_CONF,
        "-r", str(pcap_path),
        "-R", str(ruleset_path),
        "-A", "alert_fast", "-q",
    ]
    result = subprocess.run(
        env_cmd, capture_output=True, text=True,
        env={"LD_LIBRARY_PATH": "/usr/local/lib"},
    )
    return result.stdout


def parse_alerts(output: str):
    alerts = []
    for line in output.splitlines():
        m = ALERT_LINE_RE.search(line)
        if m:
            src_ip, src_port, dst_ip, dst_port = m.groups()
            alerts.append((src_ip, int(src_port), dst_ip, int(dst_port)))
    return alerts


def load_manifest(scenario: str):
    with open(PCAP_DIR / f"{scenario}_manifest.json") as f:
        return json.load(f)


def flow_key_from_manifest(entry):
    left, right = entry["flow"].split("->")
    src_ip, src_port = left.split(":")
    dst_ip, dst_port = right.split(":")
    return src_ip, int(src_port), dst_ip, int(dst_port)


def evaluate(scenario, ruleset_name, ruleset_path):
    output = run_snort3(PCAP_DIR / f"{scenario}.pcap", ruleset_path)
    alerts = parse_alerts(output)
    manifest = load_manifest(scenario)

    alerted_flows = set()
    for src_ip, src_port, dst_ip, dst_port in alerts:
        alerted_flows.add(frozenset([(src_ip, src_port), (dst_ip, dst_port)]))

    tp = fp = tn = fn = 0
    for entry in manifest:
        src_ip, src_port, dst_ip, dst_port = flow_key_from_manifest(entry)
        key = frozenset([(src_ip, src_port), (dst_ip, dst_port)])
        was_alerted = key in alerted_flows
        if entry["expected_alert"] and was_alerted:
            tp += 1
        elif entry["expected_alert"] and not was_alerted:
            fn += 1
        elif not entry["expected_alert"] and was_alerted:
            fp += 1
        else:
            tn += 1

    return {"scenario": scenario, "ruleset": ruleset_name, "total_flows": len(manifest),
            "raw_alert_lines": len(alerts), "TP": tp, "FP": fp, "TN": tn, "FN": fn}


def main():
    results = []
    for scenario in SCENARIOS:
        for ruleset_name, ruleset_path in RULESETS.items():
            r = evaluate(scenario, ruleset_name, ruleset_path)
            results.append(r)
            print(f"[{scenario:22s} | {ruleset_name:13s}] "
                  f"TP={r['TP']:3d} FP={r['FP']:3d} TN={r['TN']:3d} FN={r['FN']:3d}")
    with open(BASE / "results" / "snort3_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved -> results/snort3_results.json")


if __name__ == "__main__":
    main()
