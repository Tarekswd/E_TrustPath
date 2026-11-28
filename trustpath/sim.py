"""One simulation run: build a network, route random honest-to-honest flows for a number of epochs,
learn trust from outcomes, and report metrics for the post-warm-up epochs."""
from __future__ import annotations

import random
import statistics
import time
from dataclasses import asdict, dataclass

import networkx as nx
import numpy as np

from .agreement import AgreementTrust
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
    # "agreement": own evidence plus every reporter's pooled reports, weighted per source by how well the
    #   reporter's claims agree with the source's own observations (see agreement.py).
    # "agreement_flow_bound": agreement, plus flow binding (reports only from physically attached nodes).
    report_policy: str = "naive"
    # Forgetting: every epoch, trust evidence shrinks towards the prior by this factor (1.0 = no decay).
    trust_decay: float = 1.0
    # Exploration: this fraction of flows of a trust strategy uses the shortest path instead, to keep gathering
    # evidence about nodes the trust ranking avoids (0.0 = pure exploitation).
    explore: float = 0.0


def run(cfg: SimConfig) -> dict:
    policies = ("naive", "flow_bound", "flow_bound_weighted", "local", "agreement", "agreement_flow_bound")
    if cfg.report_policy not in policies:
        raise ValueError(f"report_policy must be one of {policies}")
    if cfg.report_policy.startswith("agreement") and cfg.attribution != "e2e":
        raise ValueError("agreement policy supports e2e attribution only")
    if not 0.0 < cfg.trust_decay <= 1.0 or not 0.0 <= cfg.explore <= 1.0:
        raise ValueError("trust_decay must be in (0, 1], explore in [0, 1]")
    if cfg.trust_decay < 1.0 and cfg.report_policy.startswith("agreement"):
        raise ValueError("trust_decay is not implemented for the agreement policy")
    net = Network(cfg.net)
    trust = TrustTable(cfg.attribution)
    local: dict[int, TrustTable] = {}  # report_policy == "local": per-source tables

    agree = AgreementTrust(cfg.net.n, max(net.ids) + 1) if cfg.report_policy.startswith("agreement") else None

    def table_of(src: int):
        if agree is not None:
            return agree.view(src)
        return local.setdefault(src, TrustTable(cfg.attribution)) if cfg.report_policy == "local" else trust
    lie_rng = random.Random(cfg.net.seed * 7919 + 3)
    accepted_fake = rejected_fake = 0

    report_bytes = 0
    report_crypto_s = 0.0

    def submit(r: OutcomeReport) -> bool:
        """Sign as the reporter, verify against the registry, apply the acceptance policy, record."""
        nonlocal report_bytes, report_crypto_s
        ident = net.ids.get(r.reporter)
        if ident is None:
            return False
        t0 = time.perf_counter()
        sig = sign_report(ident, r)
        ok = verify_report(net.registry, r, sig)
        report_crypto_s += time.perf_counter() - t0
        report_bytes += len(r.encode()) + len(sig)
        if not ok:
            return False
        if agree is not None:
            if cfg.report_policy == "agreement_flow_bound" and r.reporter not in net.phys:
                return False  # Sybils: no physical attachment, no reports
            # A source's own flows count fully for itself; every report (fabricated ones too) enters the pool.
            if r.reporter < cfg.net.n and not net.attacker_controlled(r.reporter) and r.epoch >= 0:
                agree.record_own(r.reporter, list(r.intermediates), r.delivered)
            agree.record_report(r.reporter, list(r.intermediates), r.delivered)
            return True
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
    explore_rng = random.Random(cfg.net.seed * 7919 + 4)
    honest = sorted(v for v in net.phys.nodes if not net.attacker_controlled(v))
    crashed: set[int] = set()
    true_lat = dict(nx.all_pairs_dijkstra_path_length(net.phys, weight="lat"))

    sent = delivered = exposed = unreachable = copies = fake_paths = 0
    stretch, stretch_real = [], []
    for epoch in range(cfg.epochs):
        if agree is not None:
            agree.refresh()
        if cfg.trust_decay < 1.0:
            for tb in [trust, *local.values()]:
                tb.decay(cfg.trust_decay)
        if epoch == cfg.epochs // 2:
            crashed = set(net.to_crash)
        measuring = epoch >= cfg.warmup
        for _ in range(cfg.flows_per_epoch):
            src, dst = flow_rng.sample(honest, 2)
            strategy = cfg.strategy
            if cfg.explore and explore_rng.random() < cfg.explore and strategy.startswith("trust"):
                strategy = "shortest"
            paths = select(net.view, src, dst, strategy, table_of(src), net.claimed_rel)
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
                hops = list(zip(paths[0], paths[0][1:]))
                fake = not all(net.phys.has_edge(u, v) for u, v in hops)  # colluders' fake link, counted as 1 ms
                lat = sum(net.phys.edges[u, v]["lat"] if net.phys.has_edge(u, v) else 1.0 for u, v in hops)
                stretch.append(lat / true_lat[src][dst])
                fake_paths += fake
                if not fake:
                    stretch_real.append(lat / true_lat[src][dst])

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
    w_att = w_hon = float("nan")
    if agree is not None:  # metrics on the combined view, averaged over honest sources
        agree.refresh()
        hs = [s for s in honest if s < cfg.net.n]
        liars = [v for v in sorted(net.malicious | net.sybil_ids)]
        w_att = float(agree.weights[np.ix_(hs, liars)].mean()) if liars else float("nan")
        w_hon = float(agree.weights[np.ix_(hs, hs)].sum() / max(len(hs) * (len(hs) - 1), 1))
        for v in range(cfg.net.n):
            trust.alpha[v] = float(np.mean([agree.view(s).alpha[v] for s in hs]))
            trust.beta[v] = float(np.mean([agree.view(s).beta[v] for s in hs]))
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
        "median_stretch_real": statistics.median(stretch_real) if stretch_real else float("nan"),
        "fake_link_paths": fake_paths / max(sent - unreachable, 1),
        "trust_precision": len(flagged & bad) / len(flagged) if flagged else float("nan"),
        "trust_recall": len(flagged & bad) / len(bad) if bad else float("nan"),
        "adcheck_precision": len(adflag & bad) / len(adflag) if adflag else float("nan"),
        "adcheck_recall": len(adflag & bad) / len(bad) if bad else float("nan"),
        "rejected_ads": net.rejected_ads,
        "sybils_admitted": len(net.sybil_ids),
        "fake_reports_accepted": accepted_fake,
        "fake_reports_rejected": rejected_fake,
        "honest_trust_mean": statistics.fmean(trust.trust(v) for v in honest),
        "agree_weight_to_attackers": w_att,
        "agree_weight_to_honest": w_hon,
        "malicious_trust_mean": statistics.fmean(trust.trust(v) for v in net.malicious) if net.malicious else float("nan"),
        # control-plane cost of the signature scheme (bytes exact; CPU seconds measured on this machine)
        "ad_bytes": net.ad_bytes,
        "key_bytes": net.key_bytes,
        "report_bytes_per_epoch": report_bytes / cfg.epochs,
        "ad_crypto_s": net.ad_crypto_s,
        "report_crypto_s": report_crypto_s,
    }
