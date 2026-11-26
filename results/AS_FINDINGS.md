# TrustPath AS-level findings (SIMULATED), 2026-11-25

## Setup

- **Topology:** CAIDA AS-relationships 2026-11-01, subsampled to about 1,293 ASes (300 transit + 1,000 stubs), with
  SCION-like valley-free paths.
- **Evidence and seeds:** 30 seeds per cell. Evidence is end-to-end unless per-hop receipts are enabled.
- **Hypotheses:** pre-registered in NOVELTY_PLAN.md section 3.3.
- **Data:** `as-T1-30seeds` (3,780 runs), `as-T2-30seeds` (1,440), `as-T3-30seeds` (3,960), `as-AUC-10seeds` (100).
- **Analysis output:** `hypotheses_as.txt`, `hypothesis_t3.txt`, `auc_control.txt`. All intervals are 95% t-CIs
  over seeds.

## Measurement artefact (found while checking H-T2): localisation AUC depends on attacker position

The pre-registered localisation score ranks ASes by the posterior-mean trust α/(α+β), starting from a Beta(1,1)
prior. When the "attackers" are the top-degree transit ASes, this score is shifted by position alone.

- **Attackers that never drop** (`drop=0`) score AUC 0.18-0.24 at top placement and about 0.52 at random placement.
- **The prior-free failure share** (`loc_auc_mle`) is shifted the other way, to 0.61-0.64.

Localisation is therefore reported as the lift over a placebo with the same placement and receipt setting, and
with randomly placed attackers where possible.

## Results

**H-T1 (adoption curve): partly supported.**

- With source-local trust, adopters gain over non-adopters by about +0.03 to +0.05 delivery when attackers sit at
  the top-degree ASes. The gain is flat in the adoption fraction f.
- With randomly placed attackers the gain is about 0.
- Agreement-filtered sharing adds a further +0.010 to +0.026 (paired by seed) at every f. That extra benefit grows
  only from f=0.05 to f=0.1, then plateaus.
- There is no crossover: sharing is never worse than local trust.

**H-T2 (adopter-aware attacker): supported.**

- Non-adopter delivery is the same as under a naive attacker (paired difference 0.000 +/- 0.002).
- Adopters get 0.98 delivery, while overall delivery is 0.81 at f=0.1.
- On both metrics, adopters cannot tell this attacker apart from one that never drops: the AUC equals the placebo.
  The 0.2 AUC is not "worse than chance"; it is the position artefact above.

**H-T3 (partial receipts): supported as pre-registered, but the benefit depends on the estimator.**

Share of the full-deployment improvement recovered, using the pre-registered score as lift over the placebo:

| receipts | attackers | g = 5% | g = 10% | g = 25% |
|---|---|---|---|---|
| top by degree | top-degree, 20% drop (3 strategies) | 0.92-1.00 | 0.94-0.97 | 1.00 |
| top by degree | random, 20% drop (3 strategies) | 0.54-0.66 | 0.72-0.79 | 1.00 |
| random | any | 0.03-0.24 | 0.08-0.42 | 0.23-0.37 |

Notes on this table:

- "Full deployment" means every transit AS. Top-by-degree placement covers all of them at g = 25%, because stubs
  never appear as intermediate hops.
- With attackers dropping 80% (always or on-off), end-to-end evidence already reaches AUC 0.98-1.00 at g = 0, so
  receipts cannot be evaluated there.
- Receipts do not change delivery (within +/- 0.004).
- Caveat: much of the receipts' benefit compensates for the posterior-mean estimator. With randomly placed
  attackers, the prior-free failure share from end-to-end evidence alone (AUC 0.83-0.93) roughly matches the
  posterior-mean score with full receipts (0.81-0.97). Receipts add only +0.01 to +0.04 on top of the prior-free
  share.

**H-T4 (conflicting attacker vs agreement filtering): supported.**

- Agreement filtering minus local trust: 0.000 +/- 0.002 under the conflicting attacker, against +0.02 under
  always.
- Sharing falls back to local performance and not below it.

## Deviations from the pre-registration (all added after seeing data, with reasons)

- **T3 attacker strategies and the 20% drop rate.** The pre-registered "always, 80%" setting was already saturated.
- **Placebo runs, random attacker placement and the `loc_auc_mle` metric.** These were added after the AUC control
  grid showed the position artefact.
- The pre-registered metric (`loc_auc`) remains the primary one.

## Limits

- Simulation only. The link-loss model is uniform 0.1-1% per AS link.
- One CAIDA snapshot, subsampled.
- Localisation uses only adopters' evidence.
- Zhang et al. (CoNEXT 2008) read 2026-11-25: full deployment on a single path, no partial deployment or AS
  topology, so H-T3 is not covered (NOVELTY_GATE.md). Receipts here are abstract; framing via ack-dropping is not
  modelled.
- Chiu and He (IEEE TNSE 2021) checked 2026-11-26: budgeted measurement-path selection against a link-manipulating
  attacker, fixed shortest-path routing, PoP/router-level topologies; no end-host path selection or AS topology.
  Related to H-T2/H-T4 (discriminating attacker) and H-T3 (budgeted placement); does not cover H-T3.
