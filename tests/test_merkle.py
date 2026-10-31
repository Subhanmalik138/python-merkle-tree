"""Tests for the Merkle tree."""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from merkle import MerkleTree, ProofStep  # noqa: E402


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_empty_tree_rejected():
    with pytest.raises(ValueError):
        MerkleTree([])


def test_single_leaf_root_is_leaf_hash():
    tree = MerkleTree([b"only"])
    assert tree.root == leaf_hash(b"only")
    assert tree.proof(0) == []


def test_two_leaf_root():
    tree = MerkleTree([b"a", b"b"])
    assert tree.root == node_hash(leaf_hash(b"a"), leaf_hash(b"b"))


def test_order_matters():
    assert MerkleTree([b"a", b"b"]).root != MerkleTree([b"b", b"a"]).root


def test_str_items_encoded_as_utf8():
    assert MerkleTree(["héllo"]).root == MerkleTree(["héllo".encode()]).root


def test_proof_verifies_for_every_leaf():
    items = [f"item-{i}".encode() for i in range(17)]  # odd, > power of two
    tree = MerkleTree(items)
    for i, item in enumerate(items):
        assert MerkleTree.verify_proof(item, tree.proof(i), tree.root)


def test_proof_is_logarithmic():
    tree = MerkleTree([bytes([i]) for i in range(64)])
    assert len(tree.proof(0)) <= 6
    assert len(tree.proof(63)) <= 6


def test_tampered_leaf_fails_verification():
    tree = MerkleTree([b"a", b"b", b"c"])
    assert not MerkleTree.verify_proof(b"evil", tree.proof(0), tree.root)


def test_tampered_proof_step_fails_verification():
    tree = MerkleTree([b"a", b"b", b"c", b"d"])
    proof = tree.proof(1)
    flipped = [ProofStep(b"\x00" * 32, s.sibling_is_left) for s in proof]
    assert not MerkleTree.verify_proof(b"b", flipped, tree.root)


def test_proof_for_wrong_root_fails():
    tree = MerkleTree([b"a", b"b"])
    other = MerkleTree([b"a", b"c"])
    assert not MerkleTree.verify_proof(b"a", tree.proof(0), other.root)


def test_odd_leaf_promotion_not_duplication():
    # With duplication, a 3-leaf tree's root would equal the root of
    # [a, b, c, c]; promotion gives a different (and safer) root.
    three = MerkleTree([b"a", b"b", b"c"])
    four = MerkleTree([b"a", b"b", b"c", b"c"])
    assert three.root != four.root
    # ...but the promoted leaf's proof still verifies.
    assert MerkleTree.verify_proof(b"c", three.proof(2), three.root)


def test_verify_method_and_bad_index():
    tree = MerkleTree([b"x", b"y"])
    assert tree.verify(0, b"x")
    assert not tree.verify(1, b"x")
    assert not tree.verify(99, b"x")
    with pytest.raises(IndexError):
        tree.proof(99)


def test_serialisation_round_trip():
    tree = MerkleTree([b"a", b"b", b"c", b"d", b"e"])
    data = tree.to_dict()
    rebuilt = MerkleTree.from_leaf_hashes(
        [bytes.fromhex(h) for h in data["leaf_hashes"]]
    )
    assert rebuilt.root == tree.root
    assert rebuilt.root_hex == data["root"]


def test_invalid_item_type_rejected():
    with pytest.raises(TypeError):
        MerkleTree([123])  # type: ignore[list-item]


def test_len_and_leaf_hashes():
    tree = MerkleTree([b"a", b"b", b"c"])
    assert len(tree) == 3
    assert tree.leaf_hashes == [leaf_hash(b) for b in (b"a", b"b", b"c")]
