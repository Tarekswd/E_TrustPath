"""Beta-distribution reputation from observed forwarding outcomes (never from self-reported metrics).

trust(v) = alpha / (alpha + beta), prior Beta(1, 1) -> 0.5 for any newcomer, including Sybils.

Attribution modes:
  "e2e":     only end-to-end delivery is observable. Success credits every intermediate node;
             failure spreads one unit of blame evenly over the intermediates (honest nodes on bad
             paths get blamed too - that is the cost of not having per-hop evidence).
  "per_hop": assumes authenticated per-hop receipts (as in path-validation schemes), so a failure
             is attributed to exactly the node that dropped the packet.
"""
from __future__ import annotations

from collections import defaultdict


class TrustTable:
    def __init__(self, attribution: str = "e2e"):
        if attribution not in ("e2e", "per_hop"):
            raise ValueError("attribution must be 'e2e' or 'per_hop'")
        self.attribution = attribution
        self.alpha: dict[int, float] = defaultdict(lambda: 1.0)
        self.beta: dict[int, float] = defaultdict(lambda: 1.0)

    def trust(self, v: int) -> float:
        return self.alpha[v] / (self.alpha[v] + self.beta[v])

    def observations(self, v: int) -> float:
        return self.alpha[v] + self.beta[v] - 2.0

    def decay(self, gamma: float) -> None:
        """Forgetting: shrink accumulated evidence towards the Beta(1, 1) prior (gamma = 1 keeps everything)."""
        for v in self.alpha:
            self.alpha[v] = 1.0 + gamma * (self.alpha[v] - 1.0)
            self.beta[v] = 1.0 + gamma * (self.beta[v] - 1.0)

    def record(self, intermediates: list[int], delivered: bool, dropped_at: int | None, weight: float = 1.0) -> None:
        """`weight` scales the evidence (1.0 = one full observation)."""
        if not intermediates or weight <= 0:
            return
        if delivered:
            for v in intermediates:
                self.alpha[v] += weight
        elif self.attribution == "per_hop" and dropped_at is not None:
            for v in intermediates:
                if v == dropped_at:
                    self.beta[v] += weight
                    break
                self.alpha[v] += weight  # forwarded correctly before the drop
        else:
            share = weight / len(intermediates)
            for v in intermediates:
                self.beta[v] += share

    def record_split(self, forwarded: list[int], suspects: list[int]) -> None:
        """Failure with partial evidence (assim.py receipts): credit nodes proven to have forwarded and spread
        one unit of blame over the suspects."""
        for v in forwarded:
            self.alpha[v] += 1.0
        for v in suspects:
            self.beta[v] += 1.0 / len(suspects)
