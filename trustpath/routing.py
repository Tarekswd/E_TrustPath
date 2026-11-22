"""Path selection over the authenticated routing view.

shortest      - minimum advertised latency (cross-checked: max of both endpoints' claims).
reliability   - latency + penalty from SELF-REPORTED reliability (the naive baseline liars exploit).
trust         - latency + penalty from OBSERVED trust (Beta reputation, trust.py).
trust_multi   - two node-disjoint trust paths; one copy of the packet on each.
Node penalties are charged on the edge entering an intermediate node; the destination is free.
"""
from __future__ import annotations

import math

import networkx as nx

from .trust import TrustTable

STRATEGIES = ("shortest", "reliability", "trust", "trust_multi")
LAT_SCALE = 100.0  # ms -> cost units
PENALTY = 5.0


def _weight(strategy: str, dst: int, trust: TrustTable, claimed_rel: dict[int, float]):
    def w(u, v, d):
        c = d["lat"] / LAT_SCALE
        if v == dst or strategy == "shortest":
            return c
        p = claimed_rel.get(v, 0.5) if strategy == "reliability" else trust.trust(v)
        return c + PENALTY * -math.log(max(p, 1e-9))

    return w


def select(view: nx.Graph, src: int, dst: int, strategy: str, trust: TrustTable, claimed_rel: dict[int, float]) -> list[list[int]]:
    """Return the paths to use (empty list if unreachable)."""
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy}")
    base = "trust" if strategy == "trust_multi" else strategy
    try:
        first = nx.shortest_path(view, src, dst, weight=_weight(base, dst, trust, claimed_rel))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
    if strategy != "trust_multi":
        return [first]
    rest = view.subgraph(set(view.nodes) - set(first[1:-1]))
    if len(first) == 2:
        rest = nx.restricted_view(view, [], [(src, dst)])
    try:
        second = nx.shortest_path(rest, src, dst, weight=_weight("trust", dst, trust, claimed_rel))
        return [first, second]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return [first]
