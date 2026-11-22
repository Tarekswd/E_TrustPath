"""Run: python3 -m unittest discover -s tests -v"""
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import networkx as nx  # noqa: E402

from trustpath.identity import Identity, LinkAd, Registry, SignedAd, sign_ad, verify_ad  # noqa: E402
from trustpath.network import Network, NetConfig  # noqa: E402
from trustpath.routing import select  # noqa: E402
from trustpath.sim import SimConfig, run  # noqa: E402
from trustpath.trust import TrustTable  # noqa: E402


class Identities(unittest.TestCase):
    def setUp(self):
        self.reg = Registry("controlled")
        self.a, self.b = Identity(1, 9), Identity(2, 9)
        self.reg.admit(self.a, True)
        self.reg.admit(self.b, True)

    def test_valid_ad_verifies(self):
        self.assertTrue(verify_ad(self.reg, sign_ad(self.a, LinkAd(1, 2, 10.0, 0.98, 1))))

    def test_tampered_ad_rejected(self):
        s = sign_ad(self.a, LinkAd(1, 2, 10.0, 0.98, 1))
        self.assertFalse(verify_ad(self.reg, SignedAd(LinkAd(1, 2, 1.0, 0.98, 1), s.signature)))

    def test_impersonation_rejected(self):
        forged = LinkAd(1, 2, 1.0, 1.0, 1)  # claims to be from node 1, signed by node 2
        self.assertFalse(verify_ad(self.reg, SignedAd(forged, self.b.sign(forged.encode()))))

    def test_unregistered_and_reregistration_rejected(self):
        self.assertFalse(self.reg.admit(Identity(3, 9), operator_approved=False))
        self.assertFalse(self.reg.admit(Identity(1, 123), operator_approved=True))
        self.assertTrue(Registry("open").admit(Identity(3, 9), operator_approved=False))

    def test_out_of_range_claims_rejected(self):
        self.assertFalse(verify_ad(self.reg, sign_ad(self.a, LinkAd(1, 2, 10.0, 1.5, 1))))

    def test_deterministic_keys(self):
        self.assertEqual(Identity(5, 1).public, Identity(5, 1).public)
        self.assertNotEqual(Identity(5, 1).public, Identity(5, 2).public)


class TrustMath(unittest.TestCase):
    def test_prior_and_updates(self):
        t = TrustTable("e2e")
        self.assertEqual(t.trust(7), 0.5)
        t.record([1, 2], True, None)
        self.assertAlmostEqual(t.trust(1), 2 / 3)
        t.record([1, 2], False, 2)
        self.assertAlmostEqual(t.beta[1], 1.5)  # e2e: blame shared

    def test_weighted_evidence(self):
        t = TrustTable("e2e")
        t.record([1, 2], False, None, weight=0.5)
        self.assertAlmostEqual(t.beta[1], 1.25)  # half an observation, shared over two nodes
        t.record([1], True, None, weight=0.0)
        self.assertEqual(t.alpha[1], 1.0)

    def test_per_hop_blames_only_dropper(self):
        t = TrustTable("per_hop")
        t.record([1, 2, 3], False, 2)
        self.assertEqual((t.alpha[1], t.beta[2], t.beta[3]), (2.0, 2.0, 1.0))


class ControlPlane(unittest.TestCase):
    def test_forged_ads_rejected_and_never_in_view(self):
        net = Network(NetConfig(seed=3, malicious_frac=0.2))
        self.assertGreater(net.rejected_ads, 0)
        for u, v in net.view.edges:
            self.assertTrue(net.phys.has_edge(u, v) or frozenset((u, v)) in net.fake_links)

    def test_collusion_creates_accepted_fake_links(self):
        # Documented limitation: two colluding signers can confirm a link that does not exist.
        net = Network(NetConfig(seed=3, malicious_frac=0.2, mix=("attract_drop",)))
        self.assertTrue(net.fake_links)
        self.assertTrue(all(net.view.has_edge(*tuple(l)) for l in net.fake_links))

    def test_liars_detected_by_cross_check(self):
        net = Network(NetConfig(seed=4, malicious_frac=0.2, mix=("attract_drop",), collude=False))
        flagged = {v for v, k in net.inconsistency.items() if k >= 2}
        self.assertTrue(flagged)
        self.assertTrue(flagged <= net.malicious | {u for m in net.malicious for u in net.phys.neighbors(m)})

    def test_sybils_only_with_open_admission(self):
        closed = Network(NetConfig(seed=5, malicious_frac=0.1, sybils=10, admission="controlled"))
        opened = Network(NetConfig(seed=5, malicious_frac=0.1, sybils=10, admission="open"))
        self.assertEqual(len(closed.sybil_ids), 0)
        self.assertEqual(len(opened.sybil_ids), 10)
        self.assertFalse(any(s in closed.view for s in range(100, 110)))

    def test_invalid_config_rejected(self):
        with self.assertRaises(ValueError):
            NetConfig(malicious_frac=0.95).validate()
        with self.assertRaises(ValueError):
            NetConfig(mix=("nope",)).validate()


class ReputationSybils(unittest.TestCase):
    def _run(self, policy, sybils, epochs=12):
        return run(SimConfig(NetConfig(seed=3, malicious_frac=0.1, sybils=sybils, admission="open"),
                             epochs=epochs, warmup=2, flows_per_epoch=20, fake_reports_per_epoch=5, report_policy=policy))

    def test_naive_accepts_sybil_reports_flow_bound_rejects_them(self):
        naive, bound = self._run("naive", 20), self._run("flow_bound", 20)
        # naive: all fabricated reports accepted; flow-bound: only the 10 physical attackers' reports
        self.assertEqual(naive["fake_reports_rejected"], 0)
        self.assertEqual(bound["fake_reports_accepted"], 10 * 5 * 12)
        self.assertEqual(bound["fake_reports_rejected"], 20 * 5 * 12)

    def test_sybil_reports_distort_trust_only_under_naive_policy(self):
        naive, bound = self._run("naive", 50, epochs=20), self._run("flow_bound", 50, epochs=20)
        self.assertLess(naive["honest_trust_mean"], bound["honest_trust_mean"])
        self.assertGreater(naive["malicious_trust_mean"], bound["malicious_trust_mean"])

    def test_weighted_policy_runs_and_rejects_sybils(self):
        r = self._run("flow_bound_weighted", 20)
        self.assertEqual(r["fake_reports_rejected"], 20 * 5 * 12)

    def test_unknown_policy_rejected(self):
        with self.assertRaises(ValueError):
            run(SimConfig(NetConfig(seed=1), epochs=2, warmup=1, flows_per_epoch=2, report_policy="x"))


class Routing(unittest.TestCase):
    def _diamond(self):
        g = nx.Graph()
        g.add_edge(0, 1, lat=1.0)
        g.add_edge(1, 3, lat=1.0)
        g.add_edge(0, 2, lat=5.0)
        g.add_edge(2, 3, lat=5.0)
        return g

    def test_trust_avoids_distrusted_node(self):
        t = TrustTable()
        self.assertEqual(select(self._diamond(), 0, 3, "trust", t, {})[0], [0, 1, 3])
        for _ in range(20):
            t.record([1], False, 1)
        self.assertEqual(select(self._diamond(), 0, 3, "trust", t, {})[0], [0, 2, 3])

    def test_reliability_follows_claims(self):
        self.assertEqual(select(self._diamond(), 0, 3, "reliability", TrustTable(), {1: 0.1, 2: 1.0})[0], [0, 2, 3])

    def test_multipath_disjoint(self):
        p = select(self._diamond(), 0, 3, "trust_multi", TrustTable(), {})
        self.assertEqual(len(p), 2)
        self.assertFalse(set(p[0][1:-1]) & set(p[1][1:-1]))

    def test_unreachable_returns_empty(self):
        g = self._diamond()
        g.add_node(9)
        self.assertEqual(select(g, 0, 9, "trust", TrustTable(), {}), [])


class Simulation(unittest.TestCase):
    def test_deterministic(self):
        cfg = lambda: SimConfig(NetConfig(seed=2, malicious_frac=0.1), epochs=6, warmup=2, flows_per_epoch=10)
        self.assertEqual(repr(run(cfg())), repr(run(cfg())))  # repr: NaN != NaN

    def test_no_attackers_high_delivery(self):
        r = run(SimConfig(NetConfig(seed=2), epochs=6, warmup=2, flows_per_epoch=20))
        self.assertGreater(r["delivery_ratio"], 0.8)
        self.assertEqual(r["exposure"], 0.0)

    def test_trust_beats_shortest_against_blackholes(self):
        res = {}
        for s in ("shortest", "trust"):
            res[s] = run(SimConfig(NetConfig(seed=6, malicious_frac=0.2, mix=("blackhole",)), strategy=s, epochs=30, warmup=10))
        self.assertGreater(res["trust"]["delivery_ratio"], res["shortest"]["delivery_ratio"])

    def test_forward_drop_attribution(self):
        net = Network(NetConfig(seed=8, malicious_frac=0.2, mix=("blackhole",)))
        m = min(net.malicious)
        nbrs = [v for v in net.phys.neighbors(m) if v not in net.malicious]
        if len(nbrs) < 2:
            self.skipTest("blackhole without two honest neighbours in this topology")
        ok, blamed = net.forward([nbrs[0], m, nbrs[1]], random.Random(1), set())
        self.assertFalse(ok)
        self.assertIn(blamed, (m, None))


if __name__ == "__main__":
    unittest.main()
