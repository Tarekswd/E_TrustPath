# TrustPath - Research Position

## Research questions (from the project brief) and how v0 addresses them
| # | Question | v0 status |
|---|---|---|
| 1 | Establish and verify neighbour identity | Ed25519 + registry; tested |
| 2 | Authenticate routing information | Signed LinkAds with bidirectional confirmation; tested |
| 3 | Evaluate reliability without trusting self-reports | Beta reputation from outcomes; cross-check of latency claims |
| 4 | Detect inconsistent or malicious advertisements | Latency cross-check flags; trust threshold; precision/recall reported |
| 5 | Does trust-aware routing reduce exposure? | Scenario A (simulated) |
| 6 | Trade-offs: trust vs latency / availability / overhead | Stretch, copies per flow, unreachable flows reported |
| 7 | Sybil and collusion vulnerability | Scenario C; collusion fake links demonstrated in a test |

## Novelty status (honest)
- Beta reputation and watchdog/pathrater-style avoidance of misbehaving nodes are **established**, mainly in
  ad-hoc network research.
- Authenticated path information and endhost path selection are **established** (SCION, BGPsec/RPKI).
- **Candidate contribution (hypothesis, not demonstrated):** quantify how much the *evidence model* matters.
  End-to-end outcomes only, versus authenticated per-hop receipts, as offered by path-validation schemes. Measure
  this for trust-aware path selection on authenticated topologies, including collusion and Sybil cases where
  signatures alone fail. Scenario B is the first experiment for this. Whether this specific comparison already
  exists must be checked against the literature before any novelty claim.

## Literature to verify before citing (none of these were fetched or checked during development)
- SCION architecture papers and book (ETH Zurich / Network Security Group).
- BGPsec (RFC 8205) and RPKI (RFC 6480) - number/title to be confirmed.
- Jøsang & Ismail, "The Beta Reputation System" (2002) - venue and details to be confirmed.
- Marti et al., "Mitigating routing misbehavior in mobile ad hoc networks" (watchdog/pathrater, MobiCom 2000) -
  details to be confirmed.
- Douceur, "The Sybil Attack" (IPTPS 2002) - details to be confirmed.
- Path validation work (e.g. ICING, OPT) - to be identified properly.

## Results
See the latest `results/<timestamp>/summary.md`. A summary is in docs/PAPER_DRAFT.md.
