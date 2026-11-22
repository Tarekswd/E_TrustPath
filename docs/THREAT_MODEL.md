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
| End hosts reporting delivery outcomes | Honest (v0); reporting is authenticated and not modelled |
| Per-hop receipts (`per_hop` mode only) | Unforgeable and attributable, as path-validation schemes would provide |

## Security invariants and evidence
| Invariant | Evidence |
|---|---|
| A link appears in the routing view only if both endpoints signed it | `test_forged_ads_rejected_and_never_in_view` |
| Forged, tampered and unregistered ads are rejected | `test_tampered_ad_rejected`, `test_impersonation_rejected`, `test_unregistered_and_reregistration_rejected` |
| Sybils exist only under open admission | `test_sybils_only_with_open_admission` |
| Inconsistent latency claims are flagged | `test_liars_detected_by_cross_check` |
| Trust-aware routing moves away from a node with bad outcomes | `test_trust_avoids_distrusted_node`, `test_trust_beats_shortest_against_blackholes` |

## Explicit non-guarantees
1. **Collusion defeats bidirectional confirmation.** Two colluders can confirm a link that does not exist
   (`test_collusion_creates_accepted_fake_links`). Detecting it would need data-plane evidence, such as
   latency probing or path validation.
2. **Fresh identities start neutral.** With open admission, every new Sybil starts at trust 0.5. Trust only
   limits a Sybil after it has misbehaved observably.
3. **Shared blame under `e2e` evidence.** Honest nodes on paths with malicious nodes are penalised too, which
   lowers detection precision.
4. **Honest reporters are assumed.** False outcome reports (badmouthing or ballot-stuffing) are not modelled;
   they are the obvious next attack.
5. **Simulator keys are deterministic** (derived from the seed) for reproducibility. That is acceptable only
   because nothing here protects real traffic.
