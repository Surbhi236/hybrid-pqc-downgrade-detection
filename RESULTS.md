# PQC-Aware Detection Rules for SOC Tooling — Results Report

## 1. Motivation

Literature on SOC readiness for post-quantum cryptography (PQC) repeatedly claims that
existing IDS/IPS engines misclassify legitimate PQC-hybrid TLS traffic as anomalous,
purely because of handshake size, and that no open detection logic exists to
distinguish a **legitimate hybrid handshake** from a **hybrid-downgrade attack**
(where an on-path attacker forces a PQC-capable client down to classical-only
crypto). This experiment builds and empirically tests such detection logic end
to end, using Suricata as the IDS engine.

## 2. Threat Model

- **Legitimate PQC-hybrid session**: client offers both a classical group
  (X25519) and a hybrid PQC group (X25519MLKEM768); server selects the hybrid
  group. Session is fully PQC-protected.
- **Hybrid-downgrade attack**: client offers the same groups (demonstrating
  PQC capability), but the negotiated ServerHello selects a **classical-only**
  group. This is the textbook downgrade pattern — the client's PQC protection
  is silently stripped, likely by an on-path attacker forcing classical
  negotiation (or a misconfigured/vulnerable server).
- **Classical baseline**: ordinary pre-PQC TLS 1.3 traffic, used as a control
  group to confirm neither ruleset misfires on normal traffic.

## 3. Methodology

### 3.1 Traffic generation
Byte-accurate TLS 1.3 ClientHello / ServerHello messages were hand-crafted in
Python (`scripts/tls_crafter.py`) with realistic extension structures
(SNI, supported_versions, supported_groups, key_share) and wrapped in valid
TCP three-way-handshake streams (`scripts/generate_pcaps.py`), so Suricata
dissects them exactly as it would real captured traffic.

Key sizing (grounded in real values from the literature and IETF drafts):

| Component | Size |
|---|---|
| X25519 key_share | 32 bytes |
| ML-KEM-768 (Kyber768) public key | 1184 bytes |
| Hybrid key_share (X25519 + ML-KEM-768) | ~1216 bytes |
| Group codepoint used for hybrid | `0x11EC` (X25519MLKEM768, IETF draft-ietf-tls-ecdhe-mlkem) |
| Legacy hybrid codepoint also supported | `0x6399` (X25519Kyber768Draft00) |

Resulting observed handshake sizes:

| Scenario | ClientHello | ServerHello |
|---|---|---|
| Classical | 241 B | 128 B |
| Legitimate PQC-hybrid | 1392 B | 1312 B |
| Downgrade attack | 1392 B (PQC offered) | 128 B (classical negotiated) |

The downgrade attack's signature is precisely this asymmetry: a large,
PQC-capable ClientHello followed by a small, classical-only ServerHello —
identical to what a legitimate classical session's ServerHello looks like,
which is exactly why naive size-based heuristics cannot distinguish "legitimate
classical fallback never offered PQC" from "PQC was offered and stripped."

Four pcap scenarios were generated (`pcaps/`), each with a ground-truth
manifest (`*_manifest.json`):
- `classical_baseline.pcap` — 200 flows
- `pqc_hybrid_legit.pcap` — 200 flows
- `pqc_downgrade_attack.pcap` — 100 flows
- `mixed_traffic.pcap` — 200 shuffled classical + legit-hybrid flows (no attack), simulating realistic hybrid-migration-era background traffic

### 3.2 Rulesets compared

**`legacy_naive.rules`** — represents today's generation of IDS heuristics:
a static size threshold (`dsize:>512`) with no knowledge of PQC whatsoever.
This mirrors the "IDS size heuristics" failure mode described throughout the
literature.

**`pqc_aware.rules`** — our proposed correlation logic:
1. Tag flows where the ClientHello offers a recognised hybrid PQC group
   (silent, `flowbits:noalert` — no analyst noise).
2. Tag flows where the ServerHello negotiates a hybrid group (silent —
   confirms legitimate PQC-protected session).
3. **Alert** when a ClientHello offered a hybrid PQC group but the ServerHello
   negotiated a classical-only group — the downgrade signature.
4. Flag (low-priority, informational) any oversized ClientHello that matches
   neither known classical nor known PQC group codepoints, for analyst
   triage of non-standard/proprietary KEM implementations.

### 3.3 Engine note
An implementation subtlety was found and corrected during testing: Suricata's
`alert tls` keyword ties alert emission to its internal TLS app-layer parser
state, which our simplified (non-cryptographic) synthetic handshakes can
trip into an `HANDSHAKE_INVALID_LENGTH` anomaly state, silently suppressing
otherwise-matching alerts for that flow. Rules were rewritten as protocol-
agnostic `alert tcp` with explicit `content`/`dsize` matching, which sidesteps
this dependency entirely — arguably a more faithful model of how many legacy
signature-based tools actually operate (they do not deeply validate protocol
state before alerting).

A second subtlety: Suricata does not guarantee evaluation order between two
signatures matching the *same* packet, so a flowbit set by one rule cannot
be reliably read by another rule on that same packet. Cross-signature
correlation was therefore designed to always span a packet boundary
(ClientHello sets a flag; a *later* ServerHello packet reads it), and the
same-packet catch-all rule uses direct negated content matching instead of a
same-packet flowbits dependency.

## 4. Results

| Scenario | Ruleset | TP | FP | TN | FN | False Positive Rate |
|---|---|---|---|---|---|---|
| Classical baseline (200) | Legacy-naive | 0 | 0 | 200 | 0 | 0% |
| Classical baseline (200) | PQC-aware | 0 | 0 | 200 | 0 | 0% |
| **Legit PQC-hybrid (200)** | **Legacy-naive** | 0 | **200** | 0 | 0 | **100%** |
| **Legit PQC-hybrid (200)** | **PQC-aware** | 0 | **0** | 200 | 0 | **0%** |
| Downgrade attack (100) | Legacy-naive | 100 | 0 | 0 | 0 | — (detected, but by size coincidence, not by the actual attack semantics) |
| Downgrade attack (100) | PQC-aware | 100 | 0 | 0 | 0 | — (detected via the correct signature: `sid:9000010` — PQC offered, classical negotiated) |
| **Mixed realistic traffic (200)** | **Legacy-naive** | 0 | **100** | 100 | 0 | **50%** |
| **Mixed realistic traffic (200)** | **PQC-aware** | 0 | **0** | 200 | 0 | **0%** |

### Headline finding
On realistic hybrid-migration-era traffic (`mixed_traffic`, 50/50 classical
and legitimate-PQC flows), today's naive size-threshold heuristic produces a
**50% false positive rate** — flagging every single legitimate PQC-hybrid
session as anomalous. Our proposed client/server correlation logic reduces
this to **0%**, while still achieving **100% detection** of the actual
downgrade attack, and — critically — for the semantically correct reason
(group mismatch between offer and negotiation), not an accidental size
coincidence.

## 5. Limitations (important for the paper's Discussion/Limitations section)

1. **Synthetic, non-cryptographic traffic.** Handshakes are byte-structurally
   accurate but do not perform real Diffie-Hellman/KEM operations or
   subsequent encrypted handshake messages (EncryptedExtensions, Certificate,
   Finished). This is sufficient to test *signature/framing-level* detection
   logic but not full protocol-state-machine validation.
2. **No IP fragmentation modelling.** Real networks would fragment TLS
   records exceeding path MTU (~1460B TCP MSS); our pcaps deliver each
   handshake message in a single TCP segment regardless of size. A production
   deployment must validate rule behaviour against fragmented/reassembled
   streams.
3. **Small, controlled sample.** N=700 flows across scenarios, single
   synthetic testbed, single IDS engine (Suricata 7.0.3). No Snort3
   comparison, no real production traffic capture, no ML-based fingerprinting
   engines (JA3/JA4) evaluated.
4. **Single hybrid group tested.** Only X25519MLKEM768 (+ legacy
   X25519Kyber768) codepoints are covered; Falcon/Dilithium/SPHINCS+
   certificate-level detection (as opposed to key-exchange-level detection)
   is out of scope for this artifact.
5. **Downgrade simulation is server-side only.** We model the server
   negotiating classical crypto despite a PQC-capable client offer; we do not
   model more sophisticated on-path stripping of the client's own
   supported_groups/key_share extensions before the ServerHello is even
   computed (an active MITM rewriting ClientHello itself), which would leave
   a different, and arguably even more detectable, footprint.

## 6. Suggested Next Steps (Future Work)

- Extend to real cryptographic implementations (liboqs + OpenSSL provider)
  for full protocol-state-machine validation.
- Add Snort3 rule equivalents and compare engine-specific false-positive/
  detection behaviour.
- Test against fragmented/reassembled traffic and real captured PQC-TLS
  traffic (e.g. from Cloudflare/Chrome hybrid deployments).
- Extend detection to certificate-level PQC artefacts (Dilithium/Falcon
  signature parsing, CT log ingestion).
- Publish as an open-source "PQC SOC Rule Pack" (as called for directly in
  the literature) for community validation and contribution.

## 7. Reproducing These Results

```bash
cd scripts
python3 generate_pcaps.py        # regenerate all pcap scenarios + manifests
python3 run_experiments.py       # run full ruleset x scenario matrix, prints table
cat ../results/raw_results.json  # detailed per-scenario alert data
```
