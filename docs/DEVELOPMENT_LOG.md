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
