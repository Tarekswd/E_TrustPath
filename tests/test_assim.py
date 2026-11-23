from pathlib import Path

import pytest

from trustpath import astopo
from trustpath.assim import ASConfig, blame, run

TINY = Path(__file__).parent / "data" / "tiny.as-rel2.txt"
SMALL = dict(n_transit=3, n_stubs=6, n_sources=4, k_paths=4, epochs=6, warmup=2, flows_per_epoch=40)


def tiny():
    return astopo.subsample(astopo.load(TINY), 3, 6, seed=1)


def test_load_reads_clique_and_relationships():
    g = astopo.load(TINY)
    assert g.core == {1, 2}
    assert g.customers[12] == {100, 104, 105} and g.providers[11] == {1, 2} and 11 in g.peers[10]


def test_paths_are_valley_free_and_include_shortcut():
    g = tiny()
    pf = astopo.PathFinder(g, k=8)
    ps = pf.paths(100, 104)
    assert ps[0] == (100, 12, 104)  # shortcut at the shared provider 12
    assert (100, 10, 1, 2, 12, 104) in ps  # through the core
    for s in g.nodes:
        for d in g.nodes:
            if s != d:
                assert all(astopo.valley_free(g, p) and p[0] == s and p[-1] == d for p in pf.paths(s, d))


def test_peering_shortcut():
    pf = astopo.PathFinder(tiny(), k=8)
    assert (101, 10, 11, 102) in pf.paths(101, 102)


def test_valley_free_rejects_valley():
    g = tiny()
    assert not astopo.valley_free(g, (10, 100, 12))  # down to a customer, then up again


def test_blame_receipts():
    p = (0, 1, 2, 3, 4, 9)  # source 0, intermediates 1-4, destination 9; packet last received at index 3
    assert blame(p, 3, set()) == ([], [1, 2, 3, 4])  # no receipts: e2e, everyone is a suspect
    assert blame(p, 3, {1, 2, 3, 4}) == ([1, 2], [3])  # full receipts: exactly the dropper
    assert blame(p, 3, {2}) == ([1], [2, 3, 4])  # 2 received; the drop is at 2 or later
    assert blame(p, 3, {4}) == ([], [1, 2, 3])  # 4 did not receive; the drop is before 4


def test_run_deterministic_and_groups():
    cfg = ASConfig(seed=3, adopt_frac=0.5, mal_frac=0.34, **SMALL)
    a, b = run(cfg, TINY), run(cfg, TINY)
    assert a == b
    assert a["n_malicious"] == 1 and a["flows"] > 0
    assert 0.0 <= a["delivery_adopters"] <= 1.0 and 0.0 <= a["delivery_others"] <= 1.0


def test_adopter_aware_attacker_never_hits_adopters():
    r = run(ASConfig(seed=2, adopt_frac=1.0, mal_frac=0.34, drop=1.0, attacker="adopter_aware", **SMALL), TINY)
    # only link loss (<= 1% per link) remains for adopters
    assert r["delivery_adopters"] > 0.9


def test_agreement_rejects_receipts():
    with pytest.raises(ValueError):
        run(ASConfig(policy="agreement", receipt_frac=0.5, **SMALL), TINY)


@pytest.mark.parametrize("policy", ["local", "shared", "agreement"])
def test_policies_run(policy):
    r = run(ASConfig(seed=1, adopt_frac=0.5, mal_frac=0.34, policy=policy, **SMALL), TINY)
    assert r["flows"] > 0
