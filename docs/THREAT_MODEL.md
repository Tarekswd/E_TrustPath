# TrustPath - Threat Model

## Adversary
Controls a fraction f of nodes, including their keys. Malicious nodes may drop, selectively drop, lie in their
own advertisements, collude (confirm fake links between themselves), create Sybil identities if admission is
open, and forge advertisements in other nodes' names.

## Trust boundaries and assumptions
| Component | Assumption |
|---|---|
| Registry (key -> node id) | Honest and available; admission policy `controlled` or `open` |
| Ed25519 (`cryptography` package) | Secure; signatures unforgeable |
| Outcome reports | Signed (Ed25519) and verified; attackers and Sybils may fabricate them; policy `naive` or `flow_bound` |
| Per-hop receipts (`per_hop` mode only) | Unforgeable and attributable, as path-validation schemes would provide |

## Security invariants and evidence
| Invariant | Evidence |
|---|---|
| A link appears in the routing view only if both endpoints signed it | `test_forged_ads_rejected_and_never_in_view` |
| Forged, tampered and unregistered ads are rejected | `test_tampered_ad_rejected`, `test_impersonation_rejected`, `test_unregistered_and_reregistration_rejected` |
| Sybils exist only under open admission | `test_sybils_only_with_open_admission` |
| `flow_bound` rejects Sybil reports, `naive` accepts them; naive Sybil reports distort trust | `test_naive_accepts_sybil_reports_flow_bound_rejects_them`, `test_sybil_reports_distort_trust_only_under_naive_policy` |
| Inconsistent latency claims are flagged | `test_liars_detected_by_cross_check` |
| Trust-aware routing moves away from a node with bad outcomes | `test_trust_avoids_distrusted_node`, `test_trust_beats_shortest_against_blackholes` |

## Explicit non-guarantees
1. **Collusion defeats bidirectional confirmation.** Two colluders can confirm a link that does not exist
   (`test_collusion_creates_accepted_fake_links`). Detecting it would need data-plane evidence, such as
   latency probing or path validation.
2. **Sybils amplify fabricated reports under a naive policy.** With open admission and `naive` acceptance, each
   Sybil identity adds report weight (scenario C). `flow_bound` acceptance removes that amplification, but only
   because it ties influence to physical attachment. An attacker who controls more physical nodes, or can bind
   reports to real traffic, is not stopped.
3. **Shared blame under `e2e` evidence.** Honest nodes on paths with malicious nodes are penalised too, which
   lowers detection precision.
4. **Lying physical attackers are not stopped.** Even with `flow_bound`, malicious nodes' own fabricated reports
   are accepted. In scenario C (10 % attackers, 5 fake reports each per epoch), trust-routing delivery fell from
   0.925 to 0.722 and honest nodes' mean trust collapsed to 0.26. Weighting reports by the reporter's trust was tested and makes it worse (delivery 0.584): colluders inflate each
   other's trust and so their report weight. Source-local trust (policy `local`, no report sharing) is immune to fabricated reports and Sybils in the simulation
   (delivery 0.853), at the cost of slower learning than honest shared trust (0.925).
5. **Simulator keys are deterministic** (derived from the seed) for reproducibility. That is acceptable only
   because nothing here protects real traffic.
