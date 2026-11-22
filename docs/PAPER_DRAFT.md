# Observed-Behaviour Path Selection over Authenticated Topologies: A Simulation Study

*Working draft. All results are SIMULATED (`results/20261122T152805Z/`, 360 runs, 10 seeds). Sections marked
**[TODO]** are not done. Related work is not yet verified; no novelty is claimed.*

## Abstract
In a 100-node simulated network with signed, bidirectionally confirmed link advertisements, we compare four path
selection strategies. Two route on advertised metrics: shortest latency and self-reported reliability. Two route
on observed forwarding outcomes: Beta-reputation "trust", single-path and two disjoint paths. With 10-30 %
malicious nodes (blackhole, grayhole, and liars that advertise attractive metrics), delivery with advertised
metrics falls to 0.54-0.24. Trust-aware single-path routing keeps delivery at 0.93-0.86 and lowers the share of
paths through attackers from 0.47-0.79 to 0.02-0.23. The cost is about 10 % latency stretch. Two disjoint trust
paths reach 0.99-0.95 delivery at about twice the packet copies. We also find three limits: identity-level
defences make the modelled Sybils irrelevant; trust without forgetting does not help against benign crashes; and
trust routing starves its own detector of evidence.

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

Stretch below 1 for advertised-metric strategies happens because colluders' fake 1 ms links count as 1 ms in the
stretch computation. **[TODO]** Report it separately.

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

(Mean of 10 seeds; CIs in summary.md, all half-widths at most 0.07.) Under `naive` acceptance, Sybils scale the
attack: with 50 Sybils single-path delivery drops to 0.45. `flow_bound` makes Sybils irrelevant, with results
statistically indistinguishable from 0 Sybils. But even with no Sybils, lying physical attackers lower trust-routing
delivery from 0.925 (scenario A, no lying) to 0.722, because badmouthing pushes honest nodes' trust (0.26) below the
attackers' (0.87). Multipath routing is far more robust (0.95). **[TODO]** Report weighting and consistency
checks against lying physical reporters.

### D. Benign crashes (15 % of nodes crash at epoch 20)
trust 0.724 +/- 0.079, shortest 0.730 +/- 0.023, trust_multi 0.919 +/- 0.032. Single-path trust gives no benefit,
because the reputation accumulated before the crash outweighs new failures (no decay). **[TODO]** Add forgetting
(exponential decay or a sliding window) and re-run.

### Detection
The trust threshold (< 0.35 after at least 5 observations) has recall of only 0.31-0.32 under shortest routing,
and at most 0.09 under trust routing. Trust routing avoids suspected nodes, so they stop generating evidence.
This is a known exploration-vs-exploitation tension; quantifying it is **[TODO]**.

## 3. Limitations
Simulated only; one topology family; static links; honest outcome reporters; no recommendation sharing; no trust
decay; stretch metric affected by fake links; 10 seeds.

## 4. Next experiments
Trust decay; badmouthing reporters; exploration (epsilon-greedy) to restore detection; larger topologies
(1,000 nodes); an AS-level topology; comparison against SCION-style path choice with path validation.
