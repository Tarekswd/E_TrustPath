"""One simulation run: build a network, route random honest-to-honest flows for a number of epochs,
learn trust from outcomes, and report metrics for the post-warm-up epochs."""
from __future__ import annotations

import random
import statistics
from dataclasses import asdict, dataclass

import networkx as nx

from .network import Network, NetConfig
from .routing import select
from .trust import TrustTable

DETECTION_THRESHOLD = 0.35
MIN_OBSERVATIONS = 5


@dataclass
class SimConfig:
    net: NetConfig
    strategy: str = "trust"
    attribution: str = "e2e"
    epochs: int = 40
    warmup: int = 10
    flows_per_epoch: int = 40


def run(cfg: SimConfig) -> dict:
    net = Network(cfg.net)
    trust = TrustTable(cfg.attribution)
    # Separate streams so that every strategy sees the same flows (common random numbers).
    flow_rng = random.Random(cfg.net.seed * 7919 + 1)
    loss_rng = random.Random(cfg.net.seed * 7919 + 2)
    honest = sorted(v for v in net.phys.nodes if not net.attacker_controlled(v))
    crashed: set[int] = set()
    true_lat = dict(nx.all_pairs_dijkstra_path_length(net.phys, weight="lat"))

    sent = delivered = exposed = unreachable = copies = 0
    stretch = []
    for epoch in range(cfg.epochs):
        if epoch == cfg.epochs // 2:
            crashed = set(net.to_crash)
        measuring = epoch >= cfg.warmup
        for _ in range(cfg.flows_per_epoch):
            src, dst = flow_rng.sample(honest, 2)
            paths = select(net.view, src, dst, cfg.strategy, trust, net.claimed_rel)
            if measuring:
                sent += 1
            if not paths:
                unreachable += measuring
                continue
            ok_any = False
            for p in paths:
                ok, blamed = net.forward(p, loss_rng, crashed)
                trust.record(p[1:-1], ok, blamed)
                ok_any |= ok
            if measuring:
                copies += len(paths)
                delivered += ok_any
                exposed += any(net.attacker_controlled(v) for v in paths[0][1:-1])
                lat = sum(net.phys.edges[u, v]["lat"] if net.phys.has_edge(u, v) else 1.0 for u, v in zip(paths[0], paths[0][1:]))
                stretch.append(lat / true_lat[src][dst])

    bad = net.malicious | net.sybil_ids
    observed = [v for v in trust.alpha if trust.observations(v) >= MIN_OBSERVATIONS]
    flagged = {v for v in observed if trust.trust(v) < DETECTION_THRESHOLD}
    adflag = {v for v, k in net.inconsistency.items() if k >= 2}
    return {
        **{k: v for k, v in asdict(cfg).items() if k != "net"},
        **{f"net_{k}": (",".join(v) if isinstance(v, tuple) else v) for k, v in asdict(cfg.net).items()},
        "flows": sent,
        "delivery_ratio": delivered / sent if sent else 0.0,
        "exposure": exposed / max(sent - unreachable, 1),
        "unreachable": unreachable,
        "copies_per_flow": copies / max(sent - unreachable, 1),
        "median_stretch": statistics.median(stretch) if stretch else float("nan"),
        "trust_precision": len(flagged & bad) / len(flagged) if flagged else float("nan"),
        "trust_recall": len(flagged & bad) / len(bad) if bad else float("nan"),
        "adcheck_precision": len(adflag & bad) / len(adflag) if adflag else float("nan"),
        "adcheck_recall": len(adflag & bad) / len(bad) if bad else float("nan"),
        "rejected_ads": net.rejected_ads,
        "sybils_admitted": len(net.sybil_ids),
    }
