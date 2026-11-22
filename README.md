# TrustPath (E_TrustPath)

A reproducible **simulator** for trust-aware path selection. It asks whether choosing paths by *observed*
forwarding behaviour, rather than by advertised metrics, reduces how often traffic crosses compromised or
malicious nodes, and what that costs in latency and overhead.

> **Research simulator.** All results are simulated. It does not replace BGP, is not a routing protocol for real
> networks, and has not been run on real nodes.

## Trust model (explicit)
1. **Identity is not trust.** Every node has an Ed25519 key registered in a trusted `Registry`, which plays the
   role of an RPKI- or TRC-style trust anchor. A valid signature proves only that the sender controls a
   registered key.
2. **Authenticated advertisements.** Each node signs one `LinkAd` per link. A link enters the routing view only
   if **both** endpoints advertise it with valid signatures. Forged ads, where an attacker signs in another
   node's name, are rejected.
3. **Self-reported metrics are not trusted.** The routing latency of a link is the larger of the two endpoints'
   claims. Claims that differ by more than 20 % count as an inconsistency against both endpoints. Claimed
   reliability is used only by the deliberately naive `reliability` baseline.
4. **Trust comes from outcomes.** Each node's trust is a Beta(alpha, beta) reputation updated from delivery
   outcomes of the paths it was on. Two evidence models exist:
   - `e2e`: only end-to-end delivery is observable, so blame is shared across the path.
   - `per_hop`: assumes authenticated per-hop receipts, so blame goes to the dropping node.

   Newcomers, including Sybils, start at 0.5.
5. **Signed outcome reports.** Every outcome report is signed by its reporter and checked against the registry.
   Attackers (malicious nodes and, under open admission, Sybil identities) may submit fabricated reports
   (ballot-stuffing malicious nodes, badmouthing honest ones). Two acceptance policies are compared:
   `naive` (any registered signer), `flow_bound` (only physically attached nodes, i.e. reports must be bound to
   traffic the reporter actually sent) and `flow_bound_weighted` (additionally weighted by the reporter's trust;
   this backfires, see the paper). Assumed honest: the registry.

## Strategies compared
`shortest` (advertised latency), `reliability` (self-reported reliability), `trust` (observed trust + latency),
`trust_multi` (two node-disjoint trust paths, one copy each).

## Adversaries
blackhole (drops all), grayhole (drops 30 %), attract_drop (advertises 10x lower latency and perfect reliability,
drops 80 %), colluding fake links between attract_drop nodes (a wormhole both colluders sign), impersonation
(forged ads), fabricated outcome reports from attackers and from Sybil identities (open admission), benign crashes of 15 % of nodes halfway through a run.

## Reproduce
```bash
pip install -r requirements.txt           # networkx, cryptography (matplotlib optional, for plots)
python3 -m unittest discover -s tests -v  # 26 tests
python3 experiments/run.py 10             # all scenarios, 10 seeds -> results/<timestamp>/
```

## Simulation model and limits
100-node connected random geometric graphs. Link latency is 1 + 100 x distance ms; honest link loss is drawn
uniformly from 0.1-3 %. Each run has 40 epochs x 40 random honest flows (the first 10 epochs are warm-up).
Strategies are compared with common random numbers: the same topology and the same flows per seed.
Not modelled: queueing, congestion, dynamic link metrics, BGP policy, inter-domain structure, partial deployment,
real packet forwarding.

## Relation to existing work (to be verified against the literature before any claim)
- **SCION** provides path-aware routing with authenticated path segments and endhost path choice. TrustPath's
  question is orthogonal: *which* authenticated path to choose given observed forwarding behaviour.
- **Secure routing (S-BGP, BGPsec, RPKI)** authenticates route announcements but does not measure forwarding
  behaviour.
- **Reputation-based routing in ad-hoc networks** (watchdog/pathrater-style schemes, Beta reputation) is
  established. Applying it to authenticated path selection is not novel by itself; see docs/RESEARCH.md.

Documents: [docs/RESEARCH.md](docs/RESEARCH.md) | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
[docs/PAPER_DRAFT.md](docs/PAPER_DRAFT.md) | [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md)

## License
Apache-2.0 OR MIT.
