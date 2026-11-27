# Novelty gate T: partial deployment of trust-aware path selection in a path-aware Internet

Date: 2026-11-23. Verdict: **PASS with narrowing (preliminary)**.

## Queries run
- "partial deployment path-aware networking SCION path selection reputation observed reliability malicious ASes evaluation"
- "partial deployment trust-aware reputation path selection SCION multipath malicious AS adopters evaluation"
- "partial deployment" + path selection + SCION/path-aware + adversarial ASes + reputation/monitoring
- "detecting malicious packet-dropping ASes end-to-end measurements network tomography adversarial inter-domain path selection"

## Closest prior work and how it differs
| Work | Scope | Difference |
|---|---|---|
| Lychev, Goldberg, Schapira, *BGP Security in Partial Deployment: Is the Juice Worth the Squeeze?*, SIGCOMM 2013 (doi:10.1145/2534169.2486010, arXiv 1307.2690) | Partial deployment of S*BGP | Control-plane origin/path authentication; no data-plane reputation or endhost multipath |
| Gill, Schapira, Goldberg, *Let the Market Drive Deployment*, SIGCOMM 2011 | Adoption dynamics of BGP security | Same |
| Zhang et al., *Packet-dropping Adversary Identification for Data Plane Security*, CoNEXT 2008 (ETH NetSec) | Localising packet-dropping adversaries | **Closest to H-T3.** Must read: does it consider partial deployment of the localisation scheme? If yes, H-T3 narrows to the interaction with path selection |
| Chiu et al., *Stealthy DGoS Attack against Network Tomography*, 2021 | Attacks on tomography; detection of links that discriminate between paths | Relevant to the adopter-aware/conflicting attackers (H-T2, H-T4) |
| Legner et al., EPIC, USENIX Security 2020; Kim et al., OPT, SIGCOMM 2014 | Path validation | Full-deployment mechanisms; no reputation-based selection |
| van Veen 2024 (MSc thesis, SIDN Labs); arXiv 2509.04695 (SCIONLab path dynamics); ScionPathML | Requirement-based SCION path selection; path measurements | No adversarial ASes or partial deployment |
| Buchegger & Le Boudec 2004 | Deviation test for second-hand reputation | MANET; already cited |

## Verdict and narrowing
No evaluation was found of partial deployment of reputation- or observation-based path selection on a path-aware AS
topology. H-T3 (partial receipts) is the riskiest part: it depends on Zhang et al. 2008.

## Zhang, Jain, Perrig, CoNEXT 2008 (read in full 2026-11-25, netsec.ethz.ch/publications/papers/xin_conext08.pdf)
- Setting: one source-destination path. "We assume that the source shares a pairwise symmetric key with each
  intermediate node on the path", so every node on the path runs the protocol (full deployment).
- Mechanism: secure acks with onion reports. PAAI-1: "every intermediate node sends an ack for only a selected
  fraction of data packets". PAAI-2: "only one selected intermediate node sends an ack for each data packet". The
  subset is a per-packet secret sample among nodes that all participate, not a fixed set of deploying nodes.
- Evaluation: simulation on a single example path (Figure 1), detection time and storage per protocol. No AS
  topology, no partial or incremental deployment (the words do not appear), no path selection or reputation.
- Consequence for H-T3: not covered. H-T3 asks which *fixed* fraction of ASes must deploy receipts, placed by
  degree vs at random, on a CAIDA topology, feeding end-host path selection. PAAI-2 is the closest idea (fewer
  reporting nodes per packet) and must be cited and contrasted; its onion reports are what a deployed receipt
  would use against ack-dropping framing, which our simulator abstracts away.

## Chiu and He, IEEE TNSE 2021 (checked 2026-11-26 via a question-answering pass over par.nsf.gov/servlets/purl/10219942, 14 pages; not read line by line)
Full title: *Stealthy DGoS Attack Against Network Tomography: The Role of Active Measurements*,
doi:10.1109/TNSE.2021.3070990 (the INFOCOM 2020 / ToN 2021 *DeGrading of Service Under the Watch of Network
Tomography* is the companion paper; not checked).
- Threat model: "an attacker inside the network" that controls "a subset L_m of links" and manipulates "different
  packets traversing the same link differently", "maximally degrading the performance of targeted paths without
  exposing the manipulated links to network tomography". Same family as our adopter-aware/discriminating attacker.
- Defender: chooses "the best set of measurement paths under a budget constraint" (Stackelberg game, MIQP plus a
  greedy algorithm). This is budgeted monitor placement, the closest analogue to H-T3's "which fraction of ASes
  deploy receipts, by degree vs at random".
- Not covered: routing is fixed shortest paths; no end-host path selection, reputation or trust; inference of link
  metrics, not avoidance. Topologies are PoP-level (Bics, BTN, Colt, Cogent) and router-level (AS 20965, AS 8717),
  not an AS-level Internet topology.
- Consequence: H-T2/H-T4 must cite it as the tomography analogue of a discriminating attacker; H-T3 must cite its
  budgeted path selection as related placement work. Verdict for H-T3 unchanged: the combination (fixed partial
  deployment of receipts on a CAIDA AS topology feeding end-host path selection) is not covered.

## Still to do
- Check Stefan Schmid's "End-Host Path Selection" work (seen on his homepage) and SCION path-selection papers from
  ETH NetSec, 2020-2026.

## Check of the completion-plan hypotheses (2026-11-27, before implementing docs/COMPLETION_PLAN.md)

Queries: web "on-off attack trust management forgetting factor reputation system defense"; research index "Thompson
sampling multi-armed bandit path selection adversarial packet dropping nodes reputation routing"; web "SCION
end-host path selection security malicious AS reputation path-aware networking Schmid"; the SCION publication list
(scion-architecture.net/archive/pages/publications/).

| Work | What it covers | Consequence |
|---|---|---|
| Srivatsa, Xiong, Liu, *TrustGuard*, WWW 2005 (abstract read) | reputation against "strategic malicious nodes that continuously change their behavior", fake-transaction flooding, dishonest feedback | on-off attackers vs reputation memory is a known problem: H-T5 is not a contribution by itself |
| IoT on-off detection (e.g. "A Smart Trust Management Method to Detect On-Off Attacks in the IoT"; title and snippet only) | on-off detection in trust management | same |
| Talebi et al. arXiv 1309.7367; Zhu & Modiano arXiv 1810.10637; Zhou, Cheng, Wu arXiv 1610.03348 (abstracts) | online shortest-path routing as a combinatorial bandit with end-to-end feedback, including adversarial link states | bandit / Thompson exploration for routing is known: H-T7 is an application, not a contribution |
| Pappas, Reischuk, Perrig, *FAIR*, ICNP 2015 (read, QA pass) | forwarding accountability: transit ASes mark packets, traffic-profile violations give proofs of misbehaviour; "benefits also in sparse deployment"; DDoS use case, CAIDA traces | closest new work to H-T3 (evidence under sparse deployment); no per-AS reputation, no path selection, no partial adoption of selection. Cite and contrast |
| Scherrer, Legner, Perrig, Schmid, *An Axiomatic Perspective on the Performance Effects of End-Host Path Selection*, PERFORMANCE 2021; Scherrer et al., *Incentivizing Stable Path Selection*; Lee et al., *Source-Based Path Selection: The Data Plane Perspective*, CFI 2015 (titles/snippets) | performance and stability of end-host path selection | performance, not adversarial ASes; no overlap with H-T1 to H-T4 (titles only, not read) |

Verdict:
- **Still uncovered (the contribution):** partial deployment of trust-aware path selection on an AS topology,
  the adopter-aware attacker (H-T2), partial receipts placed by degree (H-T3, now contrasted with FAIR), and the
  agreement filter under conflicting attackers (H-T4).
- **Known in general (H-T5 on-off vs forgetting, H-T6 reputation-gaming attacker, H-T7 bandit exploration):** run
  them as robustness checks of the AS-level design, citing TrustGuard and the bandit-routing papers, not as
  contributions.
- **Not novelty work (H-T8 scale):** needed for credibility only.

