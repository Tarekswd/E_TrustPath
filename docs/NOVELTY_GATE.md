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

## Still to do
- Read Zhang et al. 2008 and Chiu et al. 2021.
- Check Stefan Schmid's "End-Host Path Selection" work (seen on his homepage) and SCION path-selection papers from
  ETH NetSec, 2020-2026.
