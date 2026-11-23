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
| 7 | Sybil and collusion vulnerability | Scenario C (fabricated reports, naive vs flow-bound); collusion fake links demonstrated in a test |

## Novelty status (honest)
- Beta reputation and watchdog/pathrater-style avoidance of misbehaving nodes are **established**, mainly in
  ad-hoc network research.
- Authenticated path information and endhost path selection are **established** (SCION, BGPsec/RPKI).
- **Candidate contribution (hypothesis, not demonstrated):** quantify how much the *evidence model* matters.
  End-to-end outcomes only, versus authenticated per-hop receipts, as offered by path-validation schemes. Measure
  this for trust-aware path selection on authenticated topologies, including collusion and Sybil cases where
  signatures alone fail. Scenario B is the first experiment for this. Whether this specific comparison already
  exists must be checked against the literature before any novelty claim.

## References (verified 2026-11-22)
- L. Chuat, M. Legner, D. Basin, D. Hausheer, S. Hitz, P. Müller, A. Perrig. *The Complete Guide to SCION: From Design
  Principles to Formal Verification*. Springer, 2022. doi:10.1007/978-3-031-05288-0.
- RFC 8205, *BGPsec Protocol Specification*; RFC 6480, *An Infrastructure to Support Secure Internet Routing* (RPKI).
- R. Ismail, A. Jøsang. *The Beta Reputation System*. Bled eConference 2002.
- S. Marti, T. Giuli, K. Lai, M. Baker. *Mitigating Routing Misbehavior in Mobile Ad Hoc Networks*. MobiCom 2000,
  doi:10.1145/345910.345955.
- J. R. Douceur. *The Sybil Attack*. IPTPS 2002, LNCS, doi:10.1007/3-540-45748-8_24.
- T. H.-J. Kim et al. *Lightweight Source Authentication and Path Validation* (OPT). SIGCOMM 2014. OPT cites ICING
  (*Verifying and Enforcing Network Paths with ICING*) as its predecessor.

## Results
See the latest `results/<timestamp>/summary.md`. A summary is in docs/PAPER_DRAFT.md.

## Novelty check of agreement-weighted sharing (2026-11-23)
Not novel as a mechanism: S. Buchegger and J.-Y. Le Boudec, *A Robust Reputation System for P2P and Mobile Ad-hoc
Networks* (P2PEcon 2004) already keep a trust rating per reporter and accept second-hand information only if it
passes a "deviation test" against first-hand ratings. Our `agreement` policy is a variant of that idea. What
remains possibly distinctive is narrow: measuring how such filtering interacts with authenticated topologies,
flow-bound reporting and Sybil identities in path selection (scenario C). This still needs a targeted literature
check (e.g. on reputation in path-aware or SCION-like routing) before any claim.
