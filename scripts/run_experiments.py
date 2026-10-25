"""
run_experiments.py
-------------------
Runs Suricata across every (pcap scenario x ruleset) combination and builds
a results table comparing:
  - legacy_naive.rules   (today's naive size-threshold heuristic)
  - pqc_aware.rules      (our proposed client/server correlation logic)

Ground truth for each flow comes from the manifest json produced alongside
each pcap. We match Suricata's per-flow alerts back to ground truth to
compute false positive / true positive / false negative counts per scenario.
"""

import json
import subprocess
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE / "pcaps"
RULES_DIR = BASE / "rules"
LOG_DIR = BASE / "logs"
SURICATA_YAML = "/etc/suricata/suricata.yaml"

SCENARIOS = ["classical_baseline", "pqc_hybrid_legit", "pqc_downgrade_attack", "mixed_traffic"]
RULESETS = {
    "legacy_naive": RULES_DIR / "legacy_naive.rules",
    "pqc_aware": RULES_DIR / "pqc_aware.rules",
}


def run_suricata(pcap_path: Path, ruleset_path: Path, out_dir: Path):
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    cmd = [
        "suricata", "-c", SURICATA_YAML,
        "-r", str(pcap_path),
        "-S", str(ruleset_path),
        "-l", str(out_dir),
        "--runmode=single",
    ]
    subprocess.run(cmd, capture_output=True, text=True)
    return out_dir / "eve.json"


def parse_alerts(eve_json_path: Path):
    """Returns list of (src_ip, src_port, dst_ip, dst_port, signature) for each alert."""
    alerts = []
    if not eve_json_path.exists():
        return alerts
    with open(eve_json_path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") == "alert":
                alerts.append({
                    "src_ip": rec.get("src_ip"),
                    "src_port": rec.get("src_port"),
                    "dest_ip": rec.get("dest_ip"),
                    "dest_port": rec.get("dest_port"),
                    "signature": rec["alert"]["signature"],
                    "sid": rec["alert"]["signature_id"],
                })
    return alerts


def load_manifest(scenario: str):
    path = PCAP_DIR / f"{scenario}_manifest.json"
    with open(path) as f:
        return json.load(f)


def flow_key_from_manifest(entry):
    # manifest "flow" field looks like "192.168.1.23:41231->10.0.0.10:443"
    left, right = entry["flow"].split("->")
    src_ip, src_port = left.split(":")
    dst_ip, dst_port = right.split(":")
    return src_ip, int(src_port), dst_ip, int(dst_port)


def evaluate_scenario(scenario, ruleset_name, ruleset_path):
    pcap_path = PCAP_DIR / f"{scenario}.pcap"
    out_dir = LOG_DIR / f"{scenario}__{ruleset_name}"
    eve_path = run_suricata(pcap_path, ruleset_path, out_dir)
    alerts = parse_alerts(eve_path)
    manifest = load_manifest(scenario)

    # Build set of flows (by src_ip,src_port -> dst_ip,dst_port in EITHER direction)
    # that triggered at least one alert.
    alerted_flows = set()
    for a in alerts:
        if a["src_ip"] and a["dest_ip"]:
            alerted_flows.add(frozenset([
                (a["src_ip"], a["src_port"]),
                (a["dest_ip"], a["dest_port"]),
            ]))

    total = len(manifest)
    expected_alert_count = sum(1 for m in manifest if m["expected_alert"])
    expected_clean_count = total - expected_alert_count

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

    return {
        "scenario": scenario,
        "ruleset": ruleset_name,
        "total_flows": total,
        "expected_alerts": expected_alert_count,
        "expected_clean": expected_clean_count,
        "raw_alert_events": len(alerts),
        "true_positive_flows": tp,
        "false_positive_flows": fp,
        "true_negative_flows": tn,
        "false_negative_flows": fn,
        "alert_signatures_seen": sorted(set(a["signature"] for a in alerts)),
    }


def main():
    results = []
    for scenario in SCENARIOS:
        for ruleset_name, ruleset_path in RULESETS.items():
            r = evaluate_scenario(scenario, ruleset_name, ruleset_path)
            results.append(r)
            print(f"[{scenario:22s} | {ruleset_name:13s}] "
                  f"TP={r['true_positive_flows']:2d} FP={r['false_positive_flows']:2d} "
                  f"TN={r['true_negative_flows']:2d} FN={r['false_negative_flows']:2d}")

    with open(BASE / "results" / "raw_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved detailed results -> results/raw_results.json")


if __name__ == "__main__":
    main()
