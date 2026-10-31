"""Merkle tree with SHA-256 hashing and inclusion proofs.

A Merkle tree compresses an ordered list of data items into a single
root hash. Given the root, anyone can prove that a particular item is
in the list without seeing the whole list: the prover supplies the
``O(log n)`` sibling hashes along the path from the leaf to the root,
and the verifier recomputes the root from them.

This is the data-integrity primitive behind Git trees, certificate
transparency logs, and blockchain block headers.

Hashing scheme (second-preimage resistant, following RFC 6962):

* leaf hash  = SHA-256(0x00 || data)
* node hash  = SHA-256(0x01 || left || right)

The domain-separation prefixes stop an attacker from passing an
interior node off as a leaf (or vice versa).

An odd number of nodes on a level is handled by promoting the last
node unchanged to the next level (rather than duplicating it, which
would let a proof for one leaf double as a proof for its "twin").
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class ProofStep:
    """One step of an inclusion proof.

    ``sibling`` is the hash of the node next to the current one, and
    ``sibling_is_left`` says which side it sits on, so the verifier
    knows the concatenation order when recomputing the parent hash.
    """

    sibling: bytes
    sibling_is_left: bool


class MerkleTree:
    """An immutable Merkle tree over an ordered sequence of items.

    Items may be ``bytes`` or ``str`` (encoded as UTF-8). The tree is
    built eagerly at construction; ``root`` and ``proof`` are then
    O(1) / O(log n) lookups.
    """

    def __init__(self, items: Iterable[bytes | str]) -> None:
        leaves = [self._to_bytes(item) for item in items]
        if not leaves:
            raise ValueError("cannot build a Merkle tree from zero items")
        self._leaf_hashes: list[bytes] = [_leaf_hash(data) for data in leaves]
        self._levels: list[list[bytes]] = [self._leaf_hashes]
        self._build_levels()

    # -- construction -------------------------------------------------

    @staticmethod
    def _to_bytes(item: bytes | str) -> bytes:
        if isinstance(item, bytes):
            return item
        if isinstance(item, str):
            return item.encode("utf-8")
        raise TypeError(f"item must be bytes or str, got {type(item).__name__}")

    def _build_levels(self) -> None:
        level = self._leaf_hashes
        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level) - 1, 2):
                next_level.append(_node_hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                # Odd node out: promote it unchanged. Duplicating it
                # would create a second, fake leaf with the same hash.
                next_level.append(level[-1])
            level = next_level
            self._levels.append(level)

    # -- public API ---------------------------------------------------

    def __len__(self) -> int:
        return len(self._leaf_hashes)

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._leaf_hashes)

    @property
    def root(self) -> bytes:
        """The root hash (32 bytes)."""
        return self._levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def leaf_hashes(self) -> list[bytes]:
        return list(self._leaf_hashes)

    def proof(self, index: int) -> list[ProofStep]:
        """Inclusion proof for the leaf at ``index``.

        Raises IndexError for out-of-range indices.
        """
        if not 0 <= index < len(self._leaf_hashes):
            raise IndexError(f"leaf index {index} out of range")
        steps: list[ProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                # Current node is a left child: sibling is on the right,
                # unless it was promoted (odd node out) — then no step.
                if idx + 1 < len(level):
                    steps.append(ProofStep(level[idx + 1], sibling_is_left=False))
            else:
                steps.append(ProofStep(level[idx - 1], sibling_is_left=True))
            idx //= 2
        return steps

    def verify(self, index: int, item: bytes | str) -> bool:
        """True if ``item`` is the leaf at ``index`` of this tree."""
        if not 0 <= index < len(self._leaf_hashes):
            return False
        return _leaf_hash(self._to_bytes(item)) == self._leaf_hashes[index]

    @staticmethod
    def verify_proof(
        item: bytes | str,
        proof: Sequence[ProofStep],
        expected_root: bytes,
    ) -> bool:
        """Verify an inclusion proof without holding the tree.

        Recomputes the root from the leaf hash and the proof steps and
        compares it against ``expected_root``. Returns False (never
        raises) for a malformed or tampered proof.
        """
        current = _leaf_hash(MerkleTree._to_bytes(item))
        for step in proof:
            if step.sibling_is_left:
                current = _node_hash(step.sibling, current)
            else:
                current = _node_hash(current, step.sibling)
        return current == expected_root

    # -- (de)serialisation --------------------------------------------

    def to_dict(self) -> dict:
        """JSON-friendly form: leaf hashes plus the root."""
        return {
            "leaf_hashes": [h.hex() for h in self._leaf_hashes],
            "root": self.root_hex,
        }

    @classmethod
    def from_leaf_hashes(cls, leaf_hashes: Iterable[bytes]) -> "MerkleTree":
        """Rebuild a tree from pre-computed leaf hashes (e.g. after a
        round-trip through :meth:`to_dict`)."""
        tree = cls.__new__(cls)
        tree._leaf_hashes = list(leaf_hashes)
        if not tree._leaf_hashes:
            raise ValueError("cannot build a Merkle tree from zero items")
        tree._levels = [tree._leaf_hashes]
        tree._build_levels()
        return tree
