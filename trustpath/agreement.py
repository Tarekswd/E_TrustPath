"""Agreement-weighted shared trust ("middle ground" between source-local and fully shared trust).

Every source keeps its own Beta evidence (as in report_policy="local"). All reports also go into a shared
pool, per reporter. When source s routes, it adds reporter r's pooled evidence with weight

    w(s, r) = max(0, 1 - 2 * mean_v |trust_s(v) - trust_r(v)|)

over nodes v that both s and r have observed at least MIN_OBS times; w = 0 if they share fewer than
MIN_COMMON such nodes, and s never counts its own reports twice. A reporter whose claims contradict what
s saw itself loses influence; reporters that agree speed up s's learning. Weights are recomputed once
per epoch (stale within an epoch). Only end-to-end attribution is supported.
"""
from __future__ import annotations

import numpy as np

MIN_OBS = 1.0  # each source sees few flows per run (~18 in the default grid), so per-node evidence is sparse
MIN_COMMON = 2


class _View:
    """What routing.select needs: trust(v)."""

    def __init__(self, alpha: np.ndarray, beta: np.ndarray):
        self.alpha, self.beta = alpha, beta

    def trust(self, v: int) -> float:
        return float(self.alpha[v] / (self.alpha[v] + self.beta[v]))


class AgreementTrust:
    def __init__(self, n_nodes: int, n_ids: int):
        self.n = n_nodes
        self.own_a = np.ones((n_ids, n_nodes))  # Beta(1, 1) prior per (source, node)
        self.own_b = np.ones((n_ids, n_nodes))
        self.pos = np.zeros((n_ids, n_nodes))  # pooled evidence per reporter
        self.neg = np.zeros((n_ids, n_nodes))
        self.weights = np.zeros((n_ids, n_ids))
        self.refresh()

    @staticmethod
    def _add(a: np.ndarray, b: np.ndarray, row: int, inter: list[int], delivered: bool) -> None:
        nodes = [v for v in inter if v >= 0]
        if not nodes:
            return
        if delivered:
            a[row, nodes] += 1.0
        else:
            b[row, nodes] += 1.0 / len(nodes)

    def record_own(self, src: int, inter: list[int], delivered: bool) -> None:
        self._add(self.own_a, self.own_b, src, inter, delivered)

    def record_report(self, reporter: int, inter: list[int], delivered: bool) -> None:
        self._add(self.pos, self.neg, reporter, inter, delivered)

    def refresh(self) -> None:
        own_obs = self.own_a + self.own_b - 2.0
        own_t = self.own_a / (self.own_a + self.own_b)
        rep_obs = self.pos + self.neg
        rep_t = (1.0 + self.pos) / (2.0 + self.pos + self.neg)
        ms = (own_obs >= MIN_OBS).astype(float)  # (S, V)
        mr = (rep_obs >= MIN_OBS).astype(float)  # (R, V)
        common = ms @ mr.T  # (S, R)
        diff = np.einsum("sv,rv,srv->sr", ms, mr, np.abs(own_t[:, None, :] - rep_t[None, :, :]))
        with np.errstate(invalid="ignore", divide="ignore"):
            w = np.clip(1.0 - 2.0 * diff / common, 0.0, 1.0)
        w[common < MIN_COMMON] = 0.0
        np.fill_diagonal(w, 0.0)
        self.weights = np.nan_to_num(w)
        self._alpha = self.own_a + self.weights @ self.pos
        self._beta = self.own_b + self.weights @ self.neg

    def view(self, src: int) -> _View:
        return _View(self._alpha[src], self._beta[src])
