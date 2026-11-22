"""Physical topology, node behaviour, signed control plane, and the data plane.

Control plane: every node signs one LinkAd per physical link. A link enters the routing view only if
BOTH endpoints advertise it with valid signatures (bidirectional confirmation). The advertised latency
used for routing is the larger of the two claims, and claims that disagree by more than 20 % are
counted as an inconsistency against both endpoints.
Data plane: honest links lose packets with their own probability; malicious nodes drop forwarded
packets with their behaviour's probability. Destinations always accept.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

import networkx as nx

from .identity import Identity, LinkAd, Registry, SignedAd, sign_ad, verify_ad


@dataclass(frozen=True)
class Behavior:
    kind: str
    drop: float  # probability of dropping a packet it should forward
    lies: bool  # advertises 10x lower latency and perfect reliability to attract traffic


HONEST = Behavior("honest", 0.0, False)
BEHAVIORS = {
    "blackhole": Behavior("blackhole", 1.0, False),
    "grayhole": Behavior("grayhole", 0.3, False),
    "attract_drop": Behavior("attract_drop", 0.8, True),
}
CRASHED = Behavior("crashed", 1.0, False)  # benign failure, not an attacker
INCONSISTENCY_TOLERANCE = 0.2


@dataclass
class NetConfig:
    n: int = 100
    seed: int = 1
    malicious_frac: float = 0.0
    mix: tuple[str, ...] = ("blackhole", "grayhole", "attract_drop")
    collude: bool = True  # attract_drop nodes advertise fake 1 ms links between each other (wormhole)
    sybils: int = 0  # extra attacker identities (reputation-layer Sybils; see sim.py)
    admission: str = "controlled"
    crash_frac: float = 0.0  # honest nodes that crash halfway through the run (see sim.py)

    def validate(self) -> None:
        if self.n < 10:
            raise ValueError("n must be >= 10")
        if not 0 <= self.malicious_frac < 0.9 or not 0 <= self.crash_frac < 0.9:
            raise ValueError("fractions must be in [0, 0.9)")
        unknown = set(self.mix) - set(BEHAVIORS)
        if unknown:
            raise ValueError(f"unknown behaviours {unknown}")


def connected_geometric(n: int, rng: random.Random) -> nx.Graph:
    radius = 1.6 * math.sqrt(math.log(n) / (math.pi * n))
    for _ in range(100):
        g = nx.random_geometric_graph(n, radius, seed=rng.randrange(2**32))
        if nx.is_connected(g):
            return g
        radius *= 1.05
    raise RuntimeError("could not build a connected topology")


class Network:
    def __init__(self, cfg: NetConfig):
        cfg.validate()
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        g = connected_geometric(cfg.n, self.rng)
        pos = nx.get_node_attributes(g, "pos")
        for u, v in g.edges:
            g.edges[u, v]["lat"] = 1.0 + 100.0 * math.dist(pos[u], pos[v])
            g.edges[u, v]["loss"] = self.rng.uniform(0.001, 0.03)
        self.phys = g
        nodes = sorted(g.nodes)

        self.behavior: dict[int, Behavior] = {v: HONEST for v in nodes}
        bad = self.rng.sample(nodes, round(cfg.malicious_frac * cfg.n))
        for i, v in enumerate(sorted(bad)):
            self.behavior[v] = BEHAVIORS[cfg.mix[i % len(cfg.mix)]]
        self.malicious = set(bad)
        honest = [v for v in nodes if v not in self.malicious]
        self.to_crash = set(self.rng.sample(honest, round(cfg.crash_frac * cfg.n)))

        self.registry = Registry(cfg.admission)
        self.ids = {v: Identity(v, cfg.seed) for v in nodes}
        for ident in self.ids.values():
            self.registry.admit(ident, operator_approved=True)

        ads: list[SignedAd] = []
        for u, v in g.edges:
            for a, b in ((u, v), (v, u)):
                ads.append(self._ad(a, b, g.edges[u, v]["lat"]))

        liars = sorted(v for v in bad if self.behavior[v].lies)
        self.fake_links: set[frozenset[int]] = set()
        if cfg.collude:
            for a, b in zip(liars, liars[1:]):
                ads += [self._ad(a, b, 1.0), self._ad(b, a, 1.0)]
                self.fake_links.add(frozenset((a, b)))

        # Sybils: extra identities the attacker registers. They have no physical links (a link needs a
        # signature from an honest endpoint too); their power is in the reputation layer, where each
        # identity can submit signed outcome reports (sim.py). Admitted only under open admission.
        self.sybil_ids: set[int] = set()
        for k in range(cfg.sybils):
            sid = cfg.n + k
            self.ids[sid] = Identity(sid, cfg.seed)
            if self.registry.admit(self.ids[sid], operator_approved=False):
                self.sybil_ids.add(sid)

        # Impersonation: each malicious node forges an ad in the name of an honest neighbour,
        # claiming a 1 ms link to the attacker, signed with the attacker's own key.
        for m in sorted(bad):
            for h in sorted(g.neighbors(m)):
                if h not in self.malicious:
                    forged = LinkAd(h, m, 1.0, 1.0, 0)
                    ads.append(SignedAd(forged, self.ids[m].sign(forged.encode())))
                    break

        self.ads = ads
        self._build_view()

    def _ad(self, origin: int, neighbor: int, lat: float) -> SignedAd:
        b = self.behavior.get(origin, HONEST)
        claim_lat = lat / 10 if b.lies else lat
        claim_rel = 1.0 if b.lies else 0.98
        return sign_ad(self.ids[origin], LinkAd(origin, neighbor, claim_lat, claim_rel, 1))

    def _build_view(self) -> None:
        verified = {}
        self.rejected_ads = 0
        for s in self.ads:
            if verify_ad(self.registry, s):
                verified[(s.ad.origin, s.ad.neighbor)] = s.ad
            else:
                self.rejected_ads += 1
        view = nx.Graph()
        self.inconsistency: dict[int, int] = {}
        self.claimed_rel: dict[int, float] = {}
        for (a, b), ad in verified.items():
            self.claimed_rel[a] = min(self.claimed_rel.get(a, 1.0), ad.claimed_reliability)
            back = verified.get((b, a))
            if back is None or a > b:
                continue  # unconfirmed (one-sided) or already handled
            hi, lo = max(ad.latency_ms, back.latency_ms), min(ad.latency_ms, back.latency_ms)
            if hi > 0 and (hi - lo) / hi > INCONSISTENCY_TOLERANCE:
                for x in (a, b):
                    self.inconsistency[x] = self.inconsistency.get(x, 0) + 1
            view.add_edge(a, b, lat=hi)
        self.view = view

    def attacker_controlled(self, v: int) -> bool:
        return v in self.malicious or v in self.sybil_ids

    def forward(self, path: list[int], rng: random.Random, crashed: set[int]) -> tuple[bool, int | None]:
        """Send one packet along `path`. Returns (delivered, node blamed for the drop or None)."""
        for i in range(1, len(path)):
            u, v = path[i - 1], path[i]
            if self.phys.has_edge(u, v):
                if rng.random() < self.phys.edges[u, v]["loss"]:
                    return False, (u if i > 1 else None)
            elif not (frozenset((u, v)) in self.fake_links and self.attacker_controlled(u)):
                return False, u  # no physical link: an attacker-advertised fake link
            if v == path[-1]:
                return True, None
            b = CRASHED if v in crashed else self.behavior.get(v, HONEST)
            if rng.random() < b.drop:
                return False, v
        return True, None
