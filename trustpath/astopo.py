"""AS-level topology from CAIDA AS relationships (serial-2) and SCION-like path construction.

Topology: the Tier-1 clique from the file header ("# input clique:") is the core. A subsample keeps the core,
the `n_transit` non-core ASes with the most direct customers, and `n_stubs` random customer-free ASes that buy
transit from a kept AS. Relationships: provider->customer (-1) and peer-peer (0).

Paths (simplified SCION beaconing): an up-segment is a provider chain from an AS to a core AS. A path from s to d
joins an up-segment of s with the reversed up-segment of d. The joins are: through a common core AS, through a core
path between two core ASes, through a shortcut at a shared non-core AS, or through a peering link between the two
segments. Every path is valley-free. Per (s, d) the K shortest are kept (by AS hops, ties broken by AS numbers).
"""
from __future__ import annotations

import bz2
import random
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

MAX_UP_DEPTH = 4  # provider hops from an AS to the core
MAX_UP_SEGMENTS = 8  # per AS, the shortest ones


@dataclass
class ASGraph:
    providers: dict[int, set[int]] = field(default_factory=dict)
    customers: dict[int, set[int]] = field(default_factory=dict)
    peers: dict[int, set[int]] = field(default_factory=dict)
    core: set[int] = field(default_factory=set)

    @property
    def nodes(self) -> list[int]:
        return sorted(set(self.providers) | set(self.customers) | set(self.peers) | self.core)

    def add(self, a: int, b: int, rel: int) -> None:
        for x in (a, b):
            self.providers.setdefault(x, set())
            self.customers.setdefault(x, set())
            self.peers.setdefault(x, set())
        if rel == -1:
            self.customers[a].add(b)
            self.providers[b].add(a)
        elif rel == 0:
            self.peers[a].add(b)
            self.peers[b].add(a)


def load(path: str | Path) -> ASGraph:
    g = ASGraph()
    opener = bz2.open if str(path).endswith(".bz2") else open
    with opener(path, "rt") as fh:
        for line in fh:
            if line.startswith("# input clique:"):
                g.core = {int(x) for x in line.split(":", 1)[1].split()}
            elif line and not line.startswith("#"):
                a, b, rel = line.split("|")[:3]
                g.add(int(a), int(b), int(rel))
    if not g.core:
        raise ValueError("no '# input clique:' header line")
    return g


def subsample(g: ASGraph, n_transit: int, n_stubs: int, seed: int) -> ASGraph:
    """Deterministic for a given seed. The transit set does not depend on the seed; the stub sample does."""
    core = {a for a in g.core if a in g.providers}
    transit = sorted((a for a in g.nodes if g.customers[a] and a not in core), key=lambda a: (-len(g.customers[a]), a))
    keep = core | set(transit[:n_transit])
    stubs = sorted(a for a in g.nodes if not g.customers[a] and a not in keep and g.providers[a] & keep)
    keep |= set(random.Random(seed).sample(stubs, min(n_stubs, len(stubs))))
    h = ASGraph(core=core)
    for a in sorted(keep):
        h.add(a, a, 1)  # registers the node with no relationship (rel 1 is ignored)
        for c in g.customers[a] & keep:
            h.add(a, c, -1)
        for p in g.peers[a] & keep:
            if a < p:
                h.add(a, p, 0)
    return h


class PathFinder:
    def __init__(self, g: ASGraph, k: int = 8):
        self.g, self.k = g, k
        core_graph = nx.Graph()
        core_graph.add_nodes_from(g.core)
        for a in g.core:
            for b in (g.peers[a] | g.customers[a]) & g.core:
                core_graph.add_edge(a, b)
        self.core_paths = dict(nx.all_pairs_shortest_path(core_graph))
        self._up: dict[int, list[tuple[int, ...]]] = {}
        self._paths: dict[tuple[int, int], list[tuple[int, ...]]] = {}

    def up_segments(self, a: int) -> list[tuple[int, ...]]:
        """Provider chains from a to a core AS (a itself if a is core), shortest first."""
        if a not in self._up:
            if a in self.g.core:
                self._up[a] = [(a,)]
            else:
                done, frontier = [], [(a,)]
                for _ in range(MAX_UP_DEPTH):
                    nxt = []
                    for seg in frontier:
                        for p in sorted(self.g.providers[seg[-1]]):
                            if p in seg:
                                continue
                            (done if p in self.g.core else nxt).append(seg + (p,))
                    if len(done) >= MAX_UP_SEGMENTS:
                        break
                    frontier = nxt[: 4 * MAX_UP_SEGMENTS]  # shortcut: beam cap; raise if paths look too few
                self._up[a] = sorted(done, key=lambda s: (len(s), s))[:MAX_UP_SEGMENTS]
        return self._up[a]

    def paths(self, s: int, d: int) -> list[tuple[int, ...]]:
        key = (s, d)
        if key not in self._paths:
            found: set[tuple[int, ...]] = set()
            for up in self.up_segments(s):
                for dn in self.up_segments(d):
                    down = dn[::-1]  # core ... d
                    cp = self.core_paths.get(up[-1], {}).get(down[0])
                    if cp is not None:
                        found.add(up[:-1] + tuple(cp) + down[1:])
                    pos = {x: i for i, x in enumerate(dn)}
                    for i, x in enumerate(up):
                        if x in pos and x not in self.g.core:  # shortcut at a shared non-core AS
                            found.add(up[: i + 1] + dn[: pos[x]][::-1])
                        for y in self.g.peers[x]:  # peering shortcut
                            if y in pos and x not in self.g.core and y not in self.g.core:
                                found.add(up[: i + 1] + dn[: pos[y] + 1][::-1])
            simple = [p for p in found if len(set(p)) == len(p) and p[0] == s and p[-1] == d]
            self._paths[key] = sorted(simple, key=lambda p: (len(p), p))[: self.k]
        return self._paths[key]


def valley_free(g: ASGraph, path: tuple[int, ...]) -> bool:
    """Uphill (customer->provider) links, at most one peer or core-core link, then downhill only."""
    phase = 0  # 0 up, 1 after the top, 2 down
    for a, b in zip(path, path[1:]):
        if b in g.providers[a]:
            if phase:
                return False
        elif b in g.customers[a]:
            phase = 2
        elif b in g.peers[a]:
            if phase == 2 and not (a in g.core and b in g.core):
                return False
            phase = max(phase, 1) if a in g.core and b in g.core else 2
        else:
            return False
    return True
