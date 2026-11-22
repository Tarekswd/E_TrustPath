"""One simulation run: build a network, route random honest-to-honest flows for a number of epochs,
learn trust from outcomes, and report metrics for the post-warm-up epochs."""
from __future__ import annotations

import random
import statistics
from dataclasses import asdict, dataclass

import networkx as nx

from .identity import OutcomeReport, sign_report, verify_report
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
    # Reputation-layer attack: every attacker identity (malicious physical nodes and admitted Sybils)
    # submits this many fabricated signed reports per epoch (half ballot-stuffing a malicious node,
    # half badmouthing a random honest node). 0 = attackers do not lie in reports.
    fake_reports_per_epoch: int = 0
    # "naive": accept any report signed by a registered identity.
    # "flow_bound": accept reports only from physically attached nodes (a report must be bound to a
    #   flow the reporter actually sent; Sybils have no attachment), so influence scales with
    #   controlled nodes, not identities.
    # "flow_bound_weighted": flow_bound, and each report counts with weight = the reporter's current trust,
    #   so reporters whose own forwarding was observed to be bad lose influence.
    # "local": no report sharing; each source routes on a trust table built only from its own flows.
    report_policy: str = "naive"


def run(cfg: SimConfig) -> dict:
    if cfg.report_policy not in ("naive", "flow_bound", "flow_bound_weighted", "local"):
        raise ValueError("report_policy must be 'naive', 'flow_bound', 'flow_bound_weighted' or 'local'")
    net = Network(cfg.net)
    trust = TrustTable(cfg.attribution)
    local: dict[int, TrustTable] = {}  # report_policy == "local": per-source tables

    def table_of(src: int) -> TrustTable:
        return local.setdefault(src, TrustTable(cfg.attribution)) if cfg.report_policy == "local" else trust
    lie_rng = random.Random(cfg.net.seed * 7919 + 3)
    accepted_fake = rejected_fake = 0

    def submit(r: OutcomeReport) -> bool:
        """Sign as the reporter, verify against the registry, apply the acceptance policy, record."""
        ident = net.ids.get(r.reporter)
        if ident is None or not verify_report(net.registry, r, sign_report(ident, r)):
            return False
        if cfg.report_policy == "local":
            # Only the reporter's own table changes, so another source's routing never sees this report.
            table_of(r.reporter).record(list(r.intermediates), r.delivered, None if r.blamed < 0 else r.blamed)
            return not net.attacker_controlled(r.reporter)  # metric only: did it reach an honest table?
        if cfg.report_policy != "naive" and r.reporter not in net.phys:
            return False
        w = trust.trust(r.reporter) if cfg.report_policy == "flow_bound_weighted" else 1.0
        trust.record(list(r.intermediates), r.delivered, None if r.blamed < 0 else r.blamed, w)
        return True

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
            paths = select(net.view, src, dst, cfg.strategy, table_of(src), net.claimed_rel)
            if measuring:
                sent += 1
            if not paths:
                unreachable += measuring
                continue
            ok_any = False
            for p in paths:
                ok, blamed = net.forward(p, loss_rng, crashed)
                submit(OutcomeReport(src, tuple(p[1:-1]), ok, -1 if blamed is None else blamed, epoch))
                ok_any |= ok
            if measuring:
                copies += len(paths)
                delivered += ok_any
                exposed += any(net.attacker_controlled(v) for v in paths[0][1:-1])
                lat = sum(net.phys.edges[u, v]["lat"] if net.phys.has_edge(u, v) else 1.0 for u, v in zip(paths[0], paths[0][1:]))
                stretch.append(lat / true_lat[src][dst])

        if cfg.fake_reports_per_epoch and net.malicious:
            liars = sorted(net.malicious) + sorted(net.sybil_ids)
            mal, hon = sorted(net.malicious), honest
            for liar in liars:
                for _ in range(cfg.fake_reports_per_epoch):
                    if lie_rng.random() < 0.5:
                        r = OutcomeReport(liar, (lie_rng.choice(mal),), True, -1, epoch)
                    else:
                        h = lie_rng.choice(hon)
                        r = OutcomeReport(liar, (h,), False, h, epoch)
                    if submit(r):
                        accepted_fake += 1
                    else:
                        rejected_fake += 1

    bad = net.malicious  # physical attackers; Sybils never forward, so there is nothing to detect
    if local:  # metrics on the pooled evidence of honest sources' tables
        for src, tb in local.items():
            if not net.attacker_controlled(src):
                for v in tb.alpha:
                    trust.alpha[v] += tb.alpha[v] - 1.0
                    trust.beta[v] += tb.beta[v] - 1.0
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
        "fake_reports_accepted": accepted_fake,
        "fake_reports_rejected": rejected_fake,
        "honest_trust_mean": statistics.fmean(trust.trust(v) for v in honest),
        "malicious_trust_mean": statistics.fmean(trust.trust(v) for v in net.malicious) if net.malicious else float("nan"),
    }
