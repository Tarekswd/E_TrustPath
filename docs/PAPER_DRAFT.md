# Observed-Behaviour Path Selection over Authenticated Topologies: A Simulation Study

*Working draft. All results are SIMULATED (sections 1-2: `results/20261127T144224Z/`, 780 runs, 10 seeds; its
scenarios A-D reproduce `results/20261123T055852Z/` exactly;
section 3: CAIDA AS-level runs, 30 seeds, `results/AS_FINDINGS.md`). Sections marked
**[TODO]** are not done. Related work is partly checked (docs/NOVELTY_GATE.md); no novelty is claimed yet.*

## Abstract
In a 100-node simulated network with signed, bidirectionally confirmed link advertisements, we compare four path
selection strategies. Two route on advertised metrics: shortest latency and self-reported reliability. Two route
on observed forwarding outcomes: Beta-reputation "trust", single-path and two disjoint paths. With 10-30 %
malicious nodes (blackhole, grayhole, and liars that advertise attractive metrics), delivery with advertised
metrics falls to 0.54-0.24. Trust-aware single-path routing keeps delivery at 0.93-0.86 and lowers the share of
paths through attackers from 0.47-0.79 to 0.02-0.23. The cost is about 10 % latency stretch. Two disjoint trust
paths reach 0.99-0.95 delivery at about twice the packet copies. We also find three limits: identity-level
defences make the modelled Sybils irrelevant; trust without forgetting does not help against benign crashes; and
trust routing starves its own detector of evidence. On a CAIDA-derived AS topology (about 1,300 ASes, valley-free
paths), partial deployment still pays: adopters gain +0.03 to +0.05 delivery when attackers sit at top-degree ASes,
and per-hop receipts at the top 5 % of ASes by degree recover 0.92-1.00 of the full-deployment localisation gain
(random placement: 0.03-0.24).

## 1. Model
See README (trust model) and docs/THREAT_MODEL.md. 100-node random geometric graphs, 40 epochs x 40 flows,
10 warm-up epochs, common random numbers across strategies.

## 2. Results (simulated, mean +/- 95 % CI over 10 seeds)

### A. Malicious fraction
| f | strategy | delivery | exposure | median stretch | copies/flow |
|---|---|---|---|---|---|
| 0 | shortest | 0.939 +/- 0.005 | 0 | 1.000 | 1 |
| 0 | trust | 0.933 +/- 0.006 | 0 | 1.100 +/- 0.016 | 1 |
| 0 | trust_multi | 0.992 +/- 0.003 | 0 | 1.034 +/- 0.008 | 1.96 |
| 0.1 | shortest | 0.542 +/- 0.055 | 0.465 +/- 0.056 | 0.995 | 1 |
| 0.1 | reliability | 0.490 +/- 0.065 | 0.521 +/- 0.071 | 0.995 | 1 |
| 0.1 | trust | 0.925 +/- 0.010 | 0.023 +/- 0.029 | 1.109 +/- 0.022 | 1 |
| 0.1 | trust_multi | 0.989 +/- 0.005 | 0.000 | 1.045 +/- 0.010 | 1.96 |
| 0.2 | shortest | 0.342 +/- 0.035 | 0.687 +/- 0.038 | 0.943 | 1 |
| 0.2 | reliability | 0.305 +/- 0.034 | 0.722 +/- 0.035 | 0.944 | 1 |
| 0.2 | trust | 0.882 +/- 0.043 | 0.138 +/- 0.098 | 1.110 +/- 0.029 | 1 |
| 0.2 | trust_multi | 0.968 +/- 0.028 | 0.045 +/- 0.042 | 1.065 +/- 0.016 | 1.97 |
| 0.3 | shortest | 0.235 +/- 0.042 | 0.785 +/- 0.038 | 0.801 | 1 |
| 0.3 | reliability | 0.206 +/- 0.034 | 0.809 +/- 0.033 | 0.802 | 1 |
| 0.3 | trust | 0.860 +/- 0.027 | 0.230 +/- 0.089 | 1.130 +/- 0.037 | 1 |
| 0.3 | trust_multi | 0.954 +/- 0.018 | 0.123 +/- 0.067 | 1.076 +/- 0.026 | 1.97 |

Stretch below 1 for advertised-metric strategies comes entirely from colluders' fake 1 ms links, which count as 1 ms
in the stretch computation: 36-74 % of their paths (f = 0.1-0.3) use a fake link, and over paths without one their
median stretch is 1.000. Trust strategies never route over a fake link (0 % at every f), because the attackers
behind the fake link drop the traffic and lose trust.

### B. Evidence model (f = 0.2)
Per-hop attribution did not change delivery (trust 0.875 vs 0.882 e2e; multipath 0.971 vs 0.968; CIs overlap).
It did raise detection precision to 1.0, from 0.50 (single path, flagged in only 1 run) and 0.69. Recall stays
very low (at most 0.09) in all four configurations.

### C. Sybils in the reputation layer (f = 0.1, open admission, 5 fabricated reports per attacker identity per epoch)
Redesigned after v0, where Sybils were attached only through links no honest node would co-sign, so they had no
effect. Now every attacker identity, physical or Sybil, submits signed fabricated reports, half ballot-stuffing a
malicious node and half badmouthing a random honest node.

| Sybils | policy | trust: delivery / exposure | trust_multi: delivery / exposure | honest trust (trust) |
|---|---|---|---|---|
| 0 | either | 0.722 / 0.327 | 0.952 / 0.112 | 0.256 |
| 10 | naive | 0.600 / 0.450 | 0.896 / 0.252 | 0.186 |
| 10 | flow_bound | 0.738 / 0.321 | 0.953 / 0.119 | 0.256 |
| 50 | naive | 0.450 / 0.604 | 0.742 / 0.531 | 0.098 |
| 50 | flow_bound | 0.716 / 0.336 | 0.953 / 0.118 | 0.253 |
| 0 | flow_bound_weighted | 0.584 / 0.469 | 0.918 / 0.211 | 0.222 |
| 50 | flow_bound_weighted | 0.594 / 0.463 | 0.923 / 0.216 | 0.222 |
| 0, 10 or 50 | local | 0.853 / 0.134 | 0.962 / 0.086 | 0.799 |
| 0 | agreement | 0.866 / 0.125 | 0.987 / 0.014 | 0.611 |
| 50 | agreement | 0.618 / 0.444 | 0.921 / 0.210 | 0.333 |
| 0 | agreement_flow_bound | 0.866 / 0.125 | 0.987 / 0.014 | 0.611 |
| 50 | agreement_flow_bound | 0.865 / 0.130 | 0.987 / 0.017 | 0.611 |

(Mean of 10 seeds; CIs in summary.md, all half-widths at most 0.07.) Under `naive` acceptance, Sybils scale the
attack: with 50 Sybils single-path delivery drops to 0.45. `flow_bound` makes Sybils irrelevant, with results
statistically indistinguishable from 0 Sybils. But even with no Sybils, lying physical attackers lower trust-routing
delivery from 0.925 (scenario A, no lying) to 0.722, because badmouthing pushes honest nodes' trust (0.26) below the
attackers' (0.87). Multipath routing is far more robust (0.95). **Negative result: weighting reports by the reporter's own trust backfires.** Policy `flow_bound_weighted` keeps
flow binding and weights each report by the reporter's current trust. It lowers single-path delivery from 0.722 to
0.584 (0 Sybils), and raises attackers' mean trust from 0.868 to 0.913. Colluders ballot-stuff each other, so their
trust and report weight grow; badmouthing lowers honest nodes' trust and therefore the weight of honest reports. The
defence amplifies the very reputation that is under attack. **Source-local trust works.** With policy `local` there is no report sharing: each source routes on a trust table
built only from its own flows. Fabricated reports then never reach an honest table (0 accepted), and results are
identical for 0, 10 and 50 Sybils. Single-path delivery rises to 0.853 +/- 0.021, against 0.722 for flow binding,
and honest nodes' trust recovers (0.799 vs 0.256). The price is sparser evidence: 0.853 is below the 0.925 that
shared trust reaches when nobody lies (scenario A, f = 0.1). **Middle ground: agreement-weighted sharing (a variant of Buchegger and Le Boudec's 2004 deviation test, not a new mechanism).** Policy `agreement` keeps each source's own evidence and adds every
reporter's pooled reports, weighted per source by w = max(0, 1 - 2 * mean |own trust - reporter's trust|) over
commonly observed nodes (trustpath/agreement.py). In full runs it separates reporters well: mean weight 0.79 for
honest reporters vs 0.11 for attackers (0 Sybils). It beats source-local trust for multipath routing (0.987 +/-
0.005 vs 0.962 +/- 0.010), but many Sybils still add up: each keeps about 0.15 weight, and with 50 Sybils single-path
delivery falls to 0.618. Adding flow binding (`agreement_flow_bound`, which drops reports from identities without
physical attachment) removes that: results are flat from 0 to 50 Sybils (single path 0.865-0.866, multipath
0.987-0.989), and multipath matches shared trust when nobody lies (0.989, scenario A). Single-path delivery is
only marginally above local trust (0.866 vs 0.853, overlapping CIs). Caveat: attackers' mean trust (0.71) stays
above honest nodes' (0.61); routing still avoids them, but trust scores alone are not a reliable detector here.
Thresholds MIN_OBS = 1 and MIN_COMMON = 2 were lowered from 3/3 once, before any delivery result, because at 3/3 no
pair of sources ever shared enough evidence (all weights 0). They were not tuned on delivery results.

### D. Benign crashes (15 % of nodes crash at epoch 20)
trust 0.724 +/- 0.079, shortest 0.730 +/- 0.023, trust_multi 0.919 +/- 0.032. Single-path trust gives no benefit,
because the reputation accumulated before the crash outweighs new failures (no decay).

### E. Forgetting (benign crashes as in D)
Every epoch, each trust table's evidence shrinks towards the Beta(1, 1) prior: alpha <- 1 + g (alpha - 1), and the same
for beta.

| decay g | trust delivery | trust_multi delivery | trust stretch |
|---|---|---|---|
| 1.0 (none) | 0.724 +/- 0.079 | 0.919 +/- 0.032 | 1.104 |
| 0.9 | 0.816 +/- 0.054 | 0.946 +/- 0.022 | 1.114 |
| 0.8 | 0.862 +/- 0.034 | 0.961 +/- 0.016 | 1.127 |
| 0.7 | 0.878 +/- 0.029 | 0.968 +/- 0.015 | 1.130 |

Forgetting fixes the crash case: at g = 0.7, single-path trust beats shortest-path routing by 0.15 and two-path trust
reaches 0.968, at 2-3 % more stretch (1.104 to 1.130). Not tested: forgetting against malicious nodes. An on-off attacker can
exploit it by behaving well until its record is forgotten.

### Detection
The trust threshold (< 0.35 after at least 5 observations) has recall of only 0.31-0.32 under shortest routing,
and at most 0.09 under trust routing. Trust routing avoids suspected nodes, so they stop generating evidence.

### F. Exploration (f = 0.2)
A fraction e of each trust source's flows takes the shortest path instead, to keep gathering evidence:

| e | trust delivery | trust recall | trust_multi delivery | trust_multi recall |
|---|---|---|---|---|
| 0 | 0.882 +/- 0.043 | 0.005 +/- 0.011 | 0.968 +/- 0.028 | 0.080 +/- 0.112 |
| 0.05 | 0.865 +/- 0.043 | 0.215 +/- 0.045 | 0.940 +/- 0.027 | 0.240 +/- 0.075 |
| 0.1 | 0.833 +/- 0.041 | 0.280 +/- 0.025 | 0.912 +/- 0.026 | 0.300 +/- 0.058 |
| 0.2 | 0.788 +/- 0.033 | 0.310 +/- 0.023 | 0.847 +/- 0.025 | 0.340 +/- 0.047 |
| 0.3 | 0.734 +/- 0.034 | 0.340 +/- 0.023 | 0.783 +/- 0.027 | 0.380 +/- 0.035 |

This quantifies the tension. 5 % exploration recovers most of the detection recall (0.005 to 0.215) for a delivery
loss within the CI (0.017). At 20-30 % recall matches or exceeds shortest-path routing (0.31), but each explored
flow is exposed to attackers, so delivery falls by 0.09-0.15. Recall stays low in absolute terms because end-to-end
evidence blames every node on a failed path.

## 3. AS-level partial deployment (CAIDA, 30 seeds; details and deviations in results/AS_FINDINGS.md)
CAIDA AS relationships 2026-11-01, subsampled to about 1,293 ASes (300 transit + 1,000 stubs), SCION-like valley-free
paths. Only a fraction f of ASes adopt trust-aware selection; hypotheses H-T1 to H-T4 were pre-registered
(NOVELTY_PLAN.md section 3.3).

| Hypothesis | Result |
|---|---|
| H-T1 adoption curve | Partly supported. Adopters gain +0.03 to +0.05 delivery over non-adopters with top-degree attackers, flat in f; about 0 with random attackers. Agreement-filtered sharing adds +0.010 to +0.026 and is never worse than local trust. |
| H-T2 adopter-aware attacker | Supported. Non-adopters see no change (0.000 +/- 0.002); adopters get 0.98 delivery vs 0.81 overall at f = 0.1, and cannot distinguish this attacker from one that never drops. |
| H-T3 partial receipts | Supported, estimator-dependent. Receipts at the top 5 % / 10 % of ASes by degree recover 0.92-1.00 / 0.94-0.97 of the full-deployment localisation gain (top-degree attackers) and 0.54-0.66 / 0.72-0.79 (random attackers); random receipt placement recovers 0.03-0.42. A prior-free failure share from end-to-end evidence alone nearly matches full receipts, so receipts add only +0.01 to +0.04 over it. |
| H-T4 conflicting attacker | Supported. Agreement filtering falls back to local-trust performance (0.000 +/- 0.002), never below it. |

Measurement artefact: the posterior-mean localisation score is biased by attacker position (AUC 0.18-0.24 for
top-degree attackers that never drop), so localisation is reported as lift over a same-placement placebo.

Closest prior work: Zhang et al. (CoNEXT 2008, PAAI-1/2) assume every node on one path participates; Chiu and He
(IEEE TNSE 2021) choose measurement paths under a budget against a link-manipulating attacker, but with fixed
shortest-path routing, no end-host path selection and no AS-level topology (docs/NOVELTY_GATE.md).

## 4. Limitations
Simulated only; static links; honest outcome reporters; no recommendation sharing; forgetting
tested only against benign crashes; stretch over fake links reported separately (section 2.A); 10 seeds (30 at AS level). AS level: one subsampled CAIDA
snapshot, uniform 0.1-1 % link loss, abstract receipts (ack-dropping framing not modelled).

## 5. Next experiments
Forgetting against on-off attackers; adaptive exploration (explore more when recall is low); badmouthing reporters; larger topologies
(1,000 nodes); the full CAIDA graph; comparison against SCION-style path choice with path validation.
