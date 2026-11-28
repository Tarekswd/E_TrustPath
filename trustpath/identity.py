"""Node identities and authenticated link advertisements (Ed25519 or ML-DSA via the `cryptography` package).

A valid signature proves control of a registered key. It says nothing about honest behaviour:
trust is computed separately from observed forwarding outcomes (trust.py).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# scheme -> (private key from a 32-byte seed, public key from raw bytes). One scheme per network (Registry).
SCHEMES = {
    "ed25519": (Ed25519PrivateKey.from_private_bytes, Ed25519PublicKey.from_public_bytes),
    "mldsa44": (mldsa.MLDSA44PrivateKey.from_seed_bytes, mldsa.MLDSA44PublicKey.from_public_bytes),
    "mldsa65": (mldsa.MLDSA65PrivateKey.from_seed_bytes, mldsa.MLDSA65PublicKey.from_public_bytes),
    "mldsa87": (mldsa.MLDSA87PrivateKey.from_seed_bytes, mldsa.MLDSA87PublicKey.from_public_bytes),
}


def _verify(scheme: str, pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        SCHEMES[scheme][1](pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


class Identity:
    """Simulation identity. Keys are derived deterministically from (seed, node_id) so experiments are
    reproducible; this is acceptable only because nothing here protects real traffic."""

    def __init__(self, node_id: int, seed: int, scheme: str = "ed25519"):
        self.node_id = node_id
        self.scheme = scheme
        material = hashlib.sha256(b"trustpath-sim-key" + struct.pack(">QI", seed, node_id)).digest()
        self._sk = SCHEMES[scheme][0](material)
        self.public = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


class Registry:
    """Maps node ids to public keys (analogous to an RPKI / SCION TRC trust anchor; assumed honest).

    admission="controlled": only identities admitted by the operator (the physical nodes) are accepted.
    admission="open": anyone can register, which is what enables Sybil identities.
    """

    def __init__(self, admission: str = "controlled", scheme: str = "ed25519"):
        if admission not in ("controlled", "open"):
            raise ValueError("admission must be 'controlled' or 'open'")
        if scheme not in SCHEMES:
            raise ValueError(f"scheme must be one of {tuple(SCHEMES)}")
        self.admission = admission
        self.scheme = scheme
        self._keys: dict[int, bytes] = {}

    def admit(self, ident: Identity, operator_approved: bool) -> bool:
        if ident.node_id in self._keys or ident.scheme != self.scheme:
            return False  # first registration wins; re-registration is impersonation
        if self.admission == "controlled" and not operator_approved:
            return False
        self._keys[ident.node_id] = ident.public
        return True

    def key(self, node_id: int) -> bytes | None:
        return self._keys.get(node_id)


@dataclass(frozen=True)
class LinkAd:
    """`origin` claims a link to `neighbor` with the given latency and its own forwarding reliability."""

    origin: int
    neighbor: int
    latency_ms: float
    claimed_reliability: float
    seq: int

    def encode(self) -> bytes:
        return b"TPAD1" + struct.pack(">IIddQ", self.origin, self.neighbor, self.latency_ms, self.claimed_reliability, self.seq)


@dataclass(frozen=True)
class SignedAd:
    ad: LinkAd
    signature: bytes


def sign_ad(ident: Identity, ad: LinkAd) -> SignedAd:
    return SignedAd(ad, ident.sign(ad.encode()))


def verify_ad(reg: Registry, s: SignedAd) -> bool:
    """True iff the origin is registered and the signature verifies under the origin's key."""
    if not (0.0 <= s.ad.claimed_reliability <= 1.0) or s.ad.latency_ms < 0:
        return False
    pk = reg.key(s.ad.origin)
    return pk is not None and _verify(reg.scheme, pk, s.signature, s.ad.encode())


@dataclass(frozen=True)
class OutcomeReport:
    """`reporter` claims that a packet over `intermediates` was (not) delivered, blaming `blamed`."""

    reporter: int
    intermediates: tuple[int, ...]
    delivered: bool
    blamed: int  # -1 = none
    epoch: int

    def encode(self) -> bytes:
        return b"TPRP1" + struct.pack(f">IIiBi{len(self.intermediates)}I", self.reporter, self.epoch, self.blamed,
                                      self.delivered, len(self.intermediates), *self.intermediates)


def sign_report(ident: Identity, r: OutcomeReport) -> bytes:
    return ident.sign(r.encode())


def verify_report(reg: Registry, r: OutcomeReport, sig: bytes) -> bool:
    pk = reg.key(r.reporter)
    return pk is not None and _verify(reg.scheme, pk, sig, r.encode())
