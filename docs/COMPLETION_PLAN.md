# TrustPath completion plan

Written 2026-11-27. Goal: take TrustPath from a working simulation study (sections 1-3 of PAPER_DRAFT.md) to a
submission-ready paper with complete adversary coverage, realistic scale and baselines. Every phase lists what to
build, which files change, the tests that must exist, the experiment grid, and when the phase is done.

Runtime figures are estimates unless marked measured. Measured reference: the 100-node grid ran 780 runs in 652 s
on 15 worker processes (results/20261127T144224Z/environment.txt).

## 0. Where TrustPath stands

Built and measured:
- 100-node random geometric graphs; signed, bidirectionally confirmed link ads; blackhole, grayhole and
  attract-drop (lying) attackers with fake-link collusion; Sybils and fabricated reports; six report policies;
  benign crashes; forgetting (`trust_decay`); exploration (`explore`). Scenarios A-F, 10 seeds.
- AS level: CAIDA 2026-11-01 subsample (300 transit + 1,000 stubs), valley-free K-path selection, partial
  adoption, four attacker strategies (`always`, `on_off`, `adopter_aware`, `conflicting`), partial receipts.
  H-T1 to H-T4 tested with 30 seeds (results/AS_FINDINGS.md).

Gaps that block a submission:
1. **Forgetting is tested only against benign crashes.** An on-off attacker can wait until its record is
   forgotten (PAPER_DRAFT.md section 4). This is the most important missing experiment.
2. **No adaptive attacker** that watches its own reputation and drops only while it stays above the detection
   threshold.
3. **Exploration is a fixed fraction.** It costs 0.017-0.15 delivery for its recall gain; an adaptive rule may do
   better.
4. **Scale:** 100 nodes and a 1,300-AS subsample. Reviewers will ask about 1,000 nodes, other topology families
   and the full CAIDA graph.
5. **Baselines:** no oracle upper bound, no random-path baseline, no path-validation (per-hop receipts everywhere)
   comparison in the 100-node model.
6. **Novelty gate leftovers** (docs/NOVELTY_GATE.md "Still to do"): Stefan Schmid's end-host path selection
   work, and ETH NetSec SCION path-selection papers 2020-2026.
7. **Statistics:** confidence intervals only; no paired tests, no multiple-comparison control, no sensitivity
   analysis of PENALTY, DETECTION_THRESHOLD and MIN_OBSERVATIONS.

## 1. Rules for every phase

- **Pre-register before running.** Each new hypothesis gets a short entry (prediction, metric, test, threshold
  for "supported") in docs/HYPOTHESES.md, committed before the first full run, as was done for H-T1 to H-T4.
  Deviations are listed in the results file with reasons, as in AS_FINDINGS.md.
- **Common random numbers.** New random draws use their own `random.Random` stream, and only when the feature is
  enabled, so existing scenarios reproduce bit for bit (as trust_decay/explore do now). A test checks this.
- **Every new mechanism gets one small test** in tests/, and the full suite stays green in CI
  (`python -m pytest -v tests` plus the 1-seed smoke run, .github/workflows/ci.yml).
- **One results folder per grid**, with raw.csv, summary.md, environment.txt and figures, cited by path in the
  paper.
- **Simulated means simulated:** every figure caption and table says so.

## Phase 1: adversary completeness (100-node model)

### 1.1 On-off attackers
- Build: a new behaviour `on_off` in trustpath/network.py with `period` (epochs) and `duty` (fraction of the
  period spent dropping); the drop probability applies only in the "on" part. A matching `onoff_lie` variant that
  also advertises attractive metrics. Phase offset per attacker drawn from a dedicated RNG stream (random phases),
  plus a `synchronised` flag (all attackers on at once).
- Files: network.py (Behavior gains `period`, `duty`; `Network.forward` takes the epoch), sim.py (pass the epoch),
  run.py (scenario G), analyze.py (KEYS), tests.
- Tests: an on-off node drops only in its on-phase; with duty 1 it equals a blackhole; with duty 0 it never drops.
- Grid G (pre-registered H-T5): f = 0.2, mix all on-off; period in {4, 8, 16} epochs; duty in {0.25, 0.5};
  trust_decay in {1.0, 0.9, 0.8, 0.7}; strategies trust and trust_multi; random vs synchronised phases.
  = 3 x 2 x 4 x 2 x 2 = 96 configurations x 10 seeds = 960 runs (estimate: about 13 min at the measured rate).
- H-T5 (prediction): without decay, on-off attackers are avoided after their first on-phase, so delivery
  approaches the always-on case. With decay g, an attacker whose off-phase is longer than the forgetting horizon
  (about 1/(1-g) epochs) regains trust and causes a delivery dip at every on-phase. So the best decay depends on
  the period: there is no single g that is best for crashes (benefits from fast forgetting) and on-off
  attackers (benefit from slow forgetting).
- Done when: the decay x period interaction is quantified with CIs, and the paper states which g to use for which
  threat mix.

### 1.2 Asymmetric forgetting (the expected fix for 1.1)
- Build: `trust_decay_pos` and `trust_decay_neg` (forget good evidence faster than bad), as two parameters in
  TrustTable.decay. Option B: a sliding window (last W epochs), for comparison.
- Tests: with neg = 1, failures are never forgotten; with pos = neg the result equals symmetric decay.
- Grid: rerun G and E (crashes) with (pos, neg) in {(0.7, 1.0), (0.7, 0.9), (0.8, 0.95)} plus window
  W in {5, 10}. Expected: one setting handles both crashes and on-off attackers.
- Done when: either one setting is near-best for both threats (paper recommendation), or the paper documents the
  trade-off with numbers.

### 1.3 Reputation-aware (threshold-gaming) attacker
- Build: behaviour `adaptive`. It knows the trust rule (worst case) and drops only while its trust stays above
  DETECTION_THRESHOLD + margin. It reads the pooled table (shared policies), or its estimate of the sources'
  tables (local policy).
- Tests: an adaptive node's trust never drops below threshold + margin in a seeded run.
- Grid: margin in {0.05, 0.1, 0.2}, report policies {flow_bound, local, agreement_flow_bound}, strategies trust
  and trust_multi, decay {1.0, 0.8}.
- Pre-registered H-T6: the adaptive attacker can sustain a drop rate only up to the level that keeps its trust
  above the threshold, so its damage is bounded by the threshold choice; detection recall is 0 by construction.
  The metric that matters is the damage (delivery loss), not detection. trust_multi bounds the damage further,
  because one of the two copies usually avoids the attacker.
- Done when: the damage of the strongest attacker the model allows is reported, which gives the worst case.

### 1.4 Badmouthing plus forgetting
- Build: none new (fabricated reports exist in scenario C). Combine C with decay.
- Question: does forgetting help honest nodes recover from badmouthing faster than attackers recover from
  ballot-stuffing? Run C x decay {1.0, 0.9, 0.8}.

### 1.5 Fake-link collusion: data-plane check (optional, if time)
- Build: latency probing. A source occasionally measures the end-to-end latency of the path it used and flags
  paths whose measured latency is much larger than the advertised sum. That is evidence against links whose
  claims are false.
- Done when: the share of traffic over fake links under `shortest` and `reliability` drops, and probing cost is
  reported. Otherwise the paper keeps it as a documented non-guarantee (THREAT_MODEL.md item 1).

## Phase 2: better learning rules

### 2.1 Adaptive exploration
- Build: replace the fixed `explore` fraction with a policy choice `explore_policy`:
  - `fixed` (today);
  - `thompson`: sample each node's trust from its Beta(alpha, beta) and route on the sample. Beta reputation
    makes Thompson sampling a natural fit: uncertain nodes get explored, known-bad nodes do not;
  - `ucb`: route on an optimistic bound (mean + c * sqrt(variance));
  - `decay_eps`: exploration that shrinks as observations accumulate.
- Files: routing.py (`_weight` takes a sampled trust), sim.py, tests.
- Tests: with all nodes at the prior, Thompson routing is random among equal-cost paths; a node with
  alpha=1, beta=100 is (almost) never chosen.
- Grid F2: f in {0.1, 0.2, 0.3}, policies x parameters, trust and trust_multi.
- Pre-registered H-T7: Thompson sampling reaches recall >= 0.2 with a delivery loss <= 0.01 versus pure
  exploitation (fixed 5 % costs 0.017 for recall 0.215; results/20261127T144224Z).
- Done when: the paper recommends one exploration rule with numbers.

### 2.2 Per-hop receipts in the 100-node model at partial deployment
- Build: reuse the receipt logic from assim.py (blame narrowed between receipting nodes) in sim.py with
  `receipt_frac` and placement (random vs top degree).
- Purpose: connects the small model to H-T3 (AS level). Grid: receipt_frac {0, 0.05, 0.1, 0.25, 1.0}.
- Done when: the small-model and AS-level receipt results are compared in one figure.

## Phase 3: scale and topology diversity

### 3.1 Profile and speed up the 100-node simulator
- Measure first: profile one run (cProfile) to see whether path selection (networkx Dijkstra per flow) dominates.
- Likely fixes: cache shortest paths per (src, dst) while trust is unchanged within an epoch; use scipy.sparse.csgraph
  for Dijkstra on large graphs; only recompute weights for nodes whose trust changed.
- Done when: a 1,000-node run takes under about 2 minutes (target, to be checked), and results at 100 nodes are
  unchanged (regression test comparing summary metrics on a fixed seed).

### 3.2 Larger and different graphs
- Build: `topology` option in NetConfig: `rgg` (today), `ba` (Barabasi-Albert, scale-free hubs), `waxman`, and a
  loader for real ISP topologies (Internet Topology Zoo GraphML; check the licence and availability first).
- Grid H: n in {100, 300, 1000} x topology {rgg, ba, waxman} x f {0.1, 0.2, 0.3} x strategies, 10 seeds.
  Attackers placed at random vs at high-degree nodes (hubs are the realistic worst case in BA graphs).
- Pre-registered H-T8: trust-aware routing keeps its delivery advantage at 1,000 nodes; on BA graphs with
  attackers at the hubs the advantage shrinks, because avoiding a hub costs long detours (higher stretch).
- Done when: the delivery and stretch tables cover all cells; the paper reports where trust routing stops
  helping.

### 3.3 Full CAIDA graph at AS level
- Build: run assim.py on the full 2026-11-01 graph instead of the 1,300-AS subsample. Path computation is the
  cost: compute K valley-free paths only for the sampled (source, destination) pairs, lazily, with a cache;
  restrict sources to a sample of stub ASes.
- Also: a second and third CAIDA snapshot (e.g. 2025 and 2024) to test that results do not depend on one snapshot.
- Grid: rerun the H-T1/H-T3 headline cells (not the whole grid) on the full graph with 10 seeds.
- Done when: the headline numbers on the full graph are within the subsample's CIs, or the differences are
  reported and explained.

## Phase 4: baselines

- **Oracle:** routes around the true attacker set (upper bound on what any trust scheme can reach).
- **Random K-path choice:** lower bound for multipath without learning.
- **Full per-hop validation:** receipts at every node (EPIC/OPT-style path validation, abstracted). Shows how much
  of the oracle gap end-to-end trust closes without data-plane support.
- **Literature reputation rules** as alternative trust functions: e.g. a plain success-ratio table, and
  EigenTrust-style transitive reputation for the shared policies (check the exact formulation in the original
  paper before implementing).
- Files: routing.py (strategies `oracle`, `random_k`), sim.py, tests (oracle never routes through an attacker
  when an attacker-free path exists).
- Done when: every main table in the paper has the oracle and random rows.

## Phase 5: realism

- **Traffic:** gravity-model or heavy-tailed source/destination popularity instead of uniform pairs; weight
  delivery by flow size.
- **Dynamics:** link churn (links fail and recover), node joins; attackers that move (new attacker set every
  k epochs) to stress forgetting.
- **Loss model:** replace uniform 0.1-1 % link loss at AS level with a heavier-tailed distribution, and test
  sensitivity.
- Done when: the main conclusions are re-checked under the realistic traffic and churn settings (one table).

## Phase 6: statistics and robustness

- 30 seeds for every table that appears in the paper (10 seeds are enough while exploring).
- Paired comparisons by seed (common random numbers make this valid): paired t-test or Wilcoxon signed-rank,
  with Holm correction within each hypothesis family.
- Effect sizes with CIs, not just p-values.
- Sensitivity: PENALTY {2, 5, 10}, DETECTION_THRESHOLD {0.25, 0.35, 0.45}, MIN_OBSERVATIONS {3, 5, 10},
  LAT_SCALE; show the main conclusions hold across them.
- Done when: experiments/analyze.py emits paired tests and the sensitivity table automatically.

## Phase 7: novelty and related work

- Read and classify (as in NOVELTY_GATE.md): Schmid's end-host path selection work; ETH NetSec SCION
  path-selection papers 2020-2026; reputation systems surveys (Jøsang's Beta reputation is already cited);
  Thompson-sampling routing in overlay/multipath networks (needed once 2.1 is built).
- Rerun the systematic search the way OrbitLink did (fixed query list, every hit classified, verdict written down).
- Done when: NOVELTY_GATE.md has a final verdict for each hypothesis H-T1 to H-T8.

## Phase 8: paper and artifact

Paper outline (target length to match the venue):
1. Introduction: path-aware Internet, why advertised metrics fail, contribution list.
2. Model and threat model (THREAT_MODEL.md condensed).
3. Trust-aware path selection: Beta reputation, policies, forgetting, exploration.
4. Evaluation, small graphs: attackers incl. on-off and adaptive, forgetting, exploration, receipts.
5. Evaluation, AS level: partial deployment H-T1 to H-T4, full CAIDA.
6. Scale and topology diversity.
7. Limitations and non-guarantees.
8. Related work.
9. Conclusion.

Figures to produce: delivery vs attacker fraction (exists), decay x on-off period heat map, exploration
recall-vs-delivery frontier (fixed vs Thompson vs UCB), receipt fraction curves (small vs AS level), delivery vs
network size per topology, oracle gap bar chart.

Artifact: one command reproduces every table (`experiments/run.py` and `run_as.py` with a `--paper` flag), a
pinned requirements.txt, a Dockerfile, and a README section mapping each table and figure to its results folder.

## Novelty check result (2026-11-27) and revised priority

docs/NOVELTY_GATE.md (last section): on-off attackers vs forgetting (TrustGuard, WWW 2005), reputation-gaming
attackers, and bandit / Thompson exploration for routing (Talebi et al. 2013, Zhu & Modiano 2018, Zhou et al.
2016) are known in general. The uncovered contribution is the AS-level part: partial deployment, the
adopter-aware attacker, partial receipts by degree (contrast with FAIR, ICNP 2015) and agreement filtering.
So Phases 1.1-1.3 and 2.1 become robustness checks of the AS-level design, run in assim.py (which already has
`on_off`), not separate contributions; Phase 3.3 (full CAIDA graph) moves up because it strengthens the actual
contribution.

Revised order: 3.3 full CAIDA + snapshots, then 4 baselines at AS level (oracle, random), then 1.1/1.2 on-off and
asymmetric forgetting in assim.py, then 2.1 Thompson as one robustness row, then 6 statistics, 7 and 8. The
100-node model stays as the motivating small-scale study (sections 1-2 of the paper).

## Suggested order and effort (original, superseded by the revised order above)

| Order | Work | Why first | Effort (estimate) |
|---|---|---|---|
| 1 | 1.1 on-off + 1.2 asymmetric forgetting | the open weakness the paper already names | 1-2 days |
| 2 | 2.1 Thompson / adaptive exploration | biggest expected gain, small code change | 1 day |
| 3 | 4 baselines (oracle, random) | every later table needs them | 0.5 day |
| 4 | 1.3 adaptive attacker, 1.4 badmouthing + decay | completes the adversary model | 1-2 days |
| 5 | 3.1 profiling, 3.2 larger graphs | needs the faster simulator | 2-3 days |
| 6 | 3.3 full CAIDA, extra snapshots | slowest runs, start in background | 2-3 days |
| 7 | 6 statistics, sensitivity | before writing | 1 day |
| 8 | 7 related work, 8 paper and artifact | last | 3-5 days |
| opt | 2.2 receipts in small model, 1.5 latency probing, 5 realism | if time | 2-4 days |

Total core: about 12-18 working days of agent time plus compute, not counting review cycles.

## Definition of done for TrustPath

- Every pre-registered hypothesis H-T1 to H-T8 has a supported / not supported verdict with CIs and a paired test.
- The paper has no [TODO] markers, and every number cites a results folder.
- The full paper grid reproduces from one command in the artifact.
- NOVELTY_GATE.md has final verdicts after the Phase 7 search.
- CI is green; the test suite covers every new mechanism.
