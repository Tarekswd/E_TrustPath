# TrustPath Development Log

## 2026-11-22
### Decisions
- Python (stdlib + networkx 2.8 + cryptography 41) for the simulator, as the plan says: simulator first, no real
  nodes until the model is documented.
- Ed25519 identities with deterministic simulation keys (reproducibility); a registry as trust anchor.
- Links need both endpoints' signatures; routing latency = max of the two claims; >20 % disagreement flags both.
- Beta reputation from outcomes, with e2e and per-hop evidence modes.
- Common random numbers: the same topology and flows per seed for every strategy.

### Tested
21 unittest tests pass (identity, tamper/forgery/Sybil admission, trust math, routing, determinism, attack
scenarios). One test initially failed because NaN != NaN in a determinism comparison. It now compares `repr`.

### Results
`results/20261122T102858Z/` (300 runs, 59 s on 15 worker processes). See docs/PAPER_DRAFT.md.

### What surprised us / open problems
- The Sybil scenario has no effect (identical numbers for open and controlled admission). This follows from
  bidirectional confirmation. The scenario must be redesigned before it says anything about Sybils.
- Single-path trust does not help against benign crashes: there is no trust decay.
- Detection recall is low under trust routing (avoided nodes produce no evidence).

### Incomplete
Trust decay, malicious reporters, recommendation-based trust, larger and AS-like topologies, real-node
experiments, literature verification.

## 2026-11-22 (later) - Sybil redesign, references
- v0's Sybils were dead ends: a link needs both endpoints' signatures, so they could attach only to attackers.
  Redesigned. Sybils are reputation-layer identities, outcome reports are signed (Ed25519) and verified, and
  attackers submit fabricated reports. `naive` vs `flow_bound` acceptance.
- 3 new tests (24 total). Scenarios A, B and D reproduce the previous run exactly (checked by diff).
- Results: `results/20261122T152805Z/` (360 runs). The old results directory was replaced.
- New finding: lying physical attackers hurt single-path trust routing a lot even without Sybils.
- References verified against primary sources (SCION book, RFC 8205/6480, Beta reputation, Marti et al.,
  Douceur, OPT/ICING).

## 2026-11-22 (later) - trust-weighted reports (negative result)
- Added policy `flow_bound_weighted` (report weight = reporter's trust) and a `weight` parameter on
  `TrustTable.record`; 2 new tests (26 total).
- Result (`results/20261122T185532Z/`, 420 runs): worse than plain flow binding (trust routing 0.584 vs 0.722 delivery)
  because colluding attackers inflate each other's trust. All previously existing configurations reproduce exactly
  (checked by diff). The old results directory was replaced.
