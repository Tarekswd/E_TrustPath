"""AS-level simulation: partial deployment of trust-aware path selection over SCION-like multipath.

A set of source ASes sends flows to random destination ASes. A fraction `adopt_frac` of sources ("adopters")
choose among the K candidate paths by learned trust. The others always take the shortest candidate. Malicious
non-core transit ASes drop forwarded packets with probability `drop`, following an attacker strategy:
  always        drop every flow
  on_off        drop only in the first half of every `period`-epoch cycle
  adopter_aware drop only flows from non-adopters (adopters never see misbehaviour)
  conflicting   drop only flows from a fixed random half of all sources (sources disagree)
Trust (adopters only): `local` (each adopter learns from its own flows), `shared` (one pooled table, every
adopter reports honestly), `agreement` (agreement.py weighting; e2e evidence only).
Evidence: with no receipts, a failure is e2e (blame spread over the intermediates). A fraction `receipt_frac` of
ASes issue authenticated per-hop receipts ("I received this packet", as path validation provides). Receipts
narrow blame to the ASes between the last receipting AS that received the packet and the next receipting AS.
Assumptions: AS identities are certified (no Sybils, as with SCION TRCs), and receipts cannot be forged or
withheld by their issuer. Everything here is SIMULATED.
"""
from __future__ import annotations

import math
import random
import statistics
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from . import astopo
from .agreement import AgreementTrust
from .trust import TrustTable

PENALTY = 5.0  # as routing.py: cost = hops + PENALTY * sum(-log trust)
MIN_OBS = 3.0  # observations before an AS counts for the localisation metric
DATA = Path(__file__).resolve().parent.parent / "data" / "20261101.as-rel2.txt.bz2"
ATTACKERS = ("always", "on_off", "adopter_aware", "conflicting")
POLICIES = ("local", "shared", "agreement")


@dataclass
class ASConfig:
    seed: int = 1
    n_transit: int = 300
    n_stubs: int = 1000
    n_sources: int = 150
    k_paths: int = 8
    mal_frac: float = 0.05  # of non-core transit ASes
    mal_placement: str = "random"  # or "top" (highest customer degree)
    drop: float = 0.8
    attacker: str = "always"
    period: int = 4  # on_off cycle length in epochs
    adopt_frac: float = 0.5
    policy: str = "local"
    multipath: bool = False  # adopters send a copy on the best node-disjoint second path as well
    receipt_frac: float = 0.0
    receipt_placement: str = "random"  # or "top"
    epochs: int = 30
    warmup: int = 10
    flows_per_epoch: int = 300


@lru_cache(maxsize=1)
def _full_graph(path: str) -> astopo.ASGraph:
    return astopo.load(path)


@lru_cache(maxsize=8)
def _topology(path: str, n_transit: int, n_stubs: int, seed: int, k: int):
    g = astopo.subsample(_full_graph(path), n_transit, n_stubs, seed)
    return g, astopo.PathFinder(g, k)


def _pick(rng: random.Random, items: list[int], frac: float, placement: str, rank) -> set[int]:
    n = round(frac * len(items))
    if placement == "top":
        return set(sorted(items, key=lambda a: (-rank(a), a))[:n])
    return set(rng.sample(items, n))


def blame(path: tuple[int, ...], drop_idx: int, receipting: set[int]) -> tuple[list[int], list[int]]:
    """(forwarded, suspects) for a packet last received at path[drop_idx]. Index 0 is the source."""
    last = max([i for i in range(1, drop_idx + 1) if path[i] in receipting], default=0)
    nxt = min([i for i in range(drop_idx + 1, len(path) - 1) if path[i] in receipting], default=len(path) - 1)
    return list(path[1:last]), list(path[max(last, 1):nxt])


def run(cfg: ASConfig, data: str | Path = DATA) -> dict:
    if cfg.attacker not in ATTACKERS or cfg.policy not in POLICIES:
        raise ValueError(f"attacker in {ATTACKERS}, policy in {POLICIES}")
    if cfg.policy == "agreement" and cfg.receipt_frac > 0:
        raise ValueError("agreement policy supports e2e evidence only")
    g, pf = _topology(str(data), cfg.n_transit, cfg.n_stubs, cfg.seed, cfg.k_paths)
    rng = random.Random(cfg.seed * 7919 + 11)
    nodes = [a for a in g.nodes if pf.up_segments(a)]
    idx = {a: i for i, a in enumerate(g.nodes)}
    transit = [a for a in nodes if g.customers[a] and a not in g.core]
    deg = lambda a: len(g.customers[a])  # noqa: E731
    malicious = _pick(rng, transit, cfg.mal_frac, cfg.mal_placement, deg)
    receipting = _pick(rng, nodes, cfg.receipt_frac, cfg.receipt_placement, deg)
    sources = sorted(rng.sample([a for a in nodes if a not in malicious], cfg.n_sources))
    adopters = set(rng.sample(sources, round(cfg.adopt_frac * len(sources))))
    targeted = set(rng.sample(sources, len(sources) // 2))
    loss = {}  # per directed AS link, drawn lazily but deterministically

    def link_loss(a: int, b: int) -> float:
        if (a, b) not in loss:
            loss[(a, b)] = random.Random(f"{cfg.seed}-{min(a, b)}-{max(a, b)}").uniform(0.001, 0.01)
        return loss[(a, b)]

    src_id = {s: i for i, s in enumerate(sources)}
    tables: dict[int, TrustTable] = {}
    pooled = TrustTable("e2e")
    agree = AgreementTrust(len(idx), len(sources)) if cfg.policy == "agreement" else None

    def trust_of(src: int, a: int) -> float:
        if agree is not None:
            return agree.view(src_id[src]).trust(idx[a])
        return (pooled if cfg.policy == "shared" else tables.setdefault(src, TrustTable("e2e"))).trust(a)

    def record(src: int, path: tuple[int, ...], ok: bool, drop_idx: int) -> None:
        inter = list(path[1:-1])
        if agree is not None:
            agree.record_own(src_id[src], [idx[a] for a in inter], ok)
            agree.record_report(src_id[src], [idx[a] for a in inter], ok)
            return
        tb = pooled if cfg.policy == "shared" else tables.setdefault(src, TrustTable("e2e"))
        if ok:
            tb.record(inter, True, None)
        else:
            tb.record_split(*blame(path, drop_idx, receipting))

    def attacks(a: int, src: int, epoch: int) -> bool:
        if a not in malicious:
            return False
        if cfg.attacker == "on_off":
            return epoch % cfg.period < cfg.period // 2
        if cfg.attacker == "adopter_aware":
            return src not in adopters
        if cfg.attacker == "conflicting":
            return src in targeted
        return True

    def forward(path: tuple[int, ...], src: int, epoch: int, prng: random.Random) -> tuple[bool, int]:
        for i in range(1, len(path)):
            if prng.random() < link_loss(path[i - 1], path[i]):
                return False, i - 1
            if i == len(path) - 1:
                return True, i
            if attacks(path[i], src, epoch) and prng.random() < cfg.drop:
                return False, i
        return True, len(path) - 1

    def choose(src: int, cands: list[tuple[int, ...]]) -> list[tuple[int, ...]]:
        if src not in adopters:
            return cands[:1]

        def cost(p):
            return len(p) - 1 + PENALTY * sum(-math.log(max(trust_of(src, a), 1e-9)) for a in p[1:-1])

        ranked = sorted(cands, key=lambda p: (cost(p), len(p), p))
        if not cfg.multipath:
            return ranked[:1]
        first = set(ranked[0][1:-1])
        second = next((p for p in ranked[1:] if not first & set(p[1:-1])), None)
        return ranked[:1] + ([second] if second else [])

    flow_rng, pkt_rng = random.Random(cfg.seed * 7919 + 1), random.Random(cfg.seed * 7919 + 2)
    stats = {grp: [0, 0, 0] for grp in ("adopter", "other")}  # sent, delivered, exposed
    hops, copies, unreachable = [], 0, 0
    for epoch in range(cfg.epochs):
        if agree is not None:
            agree.refresh()
        measuring = epoch >= cfg.warmup
        for _ in range(cfg.flows_per_epoch):
            src = flow_rng.choice(sources)
            dst = flow_rng.choice(nodes)
            if dst == src:
                continue
            cands = pf.paths(src, dst)
            grp = "adopter" if src in adopters else "other"
            if not cands:
                unreachable += measuring
                continue
            chosen = choose(src, cands)
            ok_any = False
            for p in chosen:
                ok, di = forward(p, src, epoch, pkt_rng)
                ok_any |= ok
                if src in adopters:
                    record(src, p, ok, di)
            if measuring:
                st = stats[grp]
                st[0] += 1
                st[1] += ok_any
                st[2] += any(a in malicious for a in chosen[0][1:-1])
                hops.append(len(chosen[0]) - 1)
                copies += len(chosen)

    # Localisation: adopters' combined evidence on observed transit ASes.
    alpha: dict[int, float] = {}
    beta: dict[int, float] = {}
    if agree is not None:
        agree.refresh()
        ad_ids = [src_id[s] for s in sorted(adopters)]
        for a in transit:
            if ad_ids:
                alpha[a] = float(np.mean([agree.view(i).alpha[idx[a]] for i in ad_ids]))
                beta[a] = float(np.mean([agree.view(i).beta[idx[a]] for i in ad_ids]))
        obs = {a: float(np.sum(agree.own_a[ad_ids, idx[a]] + agree.own_b[ad_ids, idx[a]] - 2)) for a in transit} if ad_ids else {}
    else:
        tbs = [pooled] if cfg.policy == "shared" else [tables[s] for s in adopters if s in tables]
        for a in transit:
            alpha[a] = 1.0 + sum(t.alpha[a] - 1.0 for t in tbs if a in t.alpha)
            beta[a] = 1.0 + sum(t.beta[a] - 1.0 for t in tbs if a in t.beta)
        obs = {a: alpha[a] + beta[a] - 2.0 for a in transit}
    seen = [a for a in transit if obs.get(a, 0.0) >= MIN_OBS]
    tr = {a: alpha[a] / (alpha[a] + beta[a]) for a in seen}
    bad = [tr[a] for a in seen if a in malicious]
    good = [tr[a] for a in seen if a not in malicious]
    auc = (sum((h > m) + 0.5 * (h == m) for h in good for m in bad) / (len(good) * len(bad))) if bad and good else float("nan")
    # Same ranking by the observed failure share, without the Beta(1,1) prior: the posterior mean above shrinks
    # rarely observed ASes towards 0.5, so it ranks heavily used (high-degree) ASes as more trustworthy even when
    # every AS behaves the same (AUC control grid: ~0.2 with non-dropping "attackers" at top placement).
    fail = {a: (beta[a] - 1.0) / (alpha[a] + beta[a] - 2.0) if alpha[a] + beta[a] > 2.0 else 0.0 for a in seen}
    fbad = [fail[a] for a in seen if a in malicious]
    fgood = [fail[a] for a in seen if a not in malicious]
    auc_mle = (sum((m > h) + 0.5 * (m == h) for h in fgood for m in fbad) / (len(fgood) * len(fbad))
               if fbad and fgood else float("nan"))

    def ratio(i, grp):
        return stats[grp][i] / stats[grp][0] if stats[grp][0] else float("nan")

    sent = stats["adopter"][0] + stats["other"][0]
    return {
        **asdict(cfg),
        "n_ases": len(nodes),
        "n_malicious": len(malicious),
        "n_receipting": len(receipting),
        "flows": sent,
        "delivery_adopters": ratio(1, "adopter"),
        "delivery_others": ratio(1, "other"),
        "delivery_all": (stats["adopter"][1] + stats["other"][1]) / sent if sent else float("nan"),
        "exposure_adopters": ratio(2, "adopter"),
        "exposure_others": ratio(2, "other"),
        "mean_hops": statistics.fmean(hops) if hops else float("nan"),
        "copies_per_flow": copies / sent if sent else float("nan"),
        "unreachable": unreachable,
        "loc_auc": auc,
        "loc_auc_mle": auc_mle,
        "loc_observed_malicious": len(bad),
    }
