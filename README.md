# Merkle Tree

A SHA-256 Merkle tree with inclusion proofs — the data-integrity
primitive behind Git trees, certificate transparency logs, and
blockchain block headers.

A Merkle tree compresses an ordered list of items into a single root
hash. Given only the root, anyone can prove that a particular item
belongs to the list by supplying the `O(log n)` sibling hashes along
the path from leaf to root. The verifier recomputes the root from
those hashes; no need to see the other items.

## Design decisions

1. **Domain-separated hashing (RFC 6962 style).** Leaf hashes are
   `SHA-256(0x00 || data)` and node hashes are
   `SHA-256(0x01 || left || right)`. Without the prefixes, an attacker
   could pass an interior node off as a leaf — a classic
   second-preimage attack on naive Merkle trees.
2. **Odd nodes are promoted, not duplicated.** When a level has an odd
   number of nodes, the last one moves up unchanged. Duplicating it
   (the Bitcoin approach) would let one leaf's proof double as a proof
   for a phantom twin leaf.
3. **Immutable, eager construction.** The tree is built once at
   construction; `root` is then O(1) and `proof(index)` is O(log n).
   Proofs are plain data (`ProofStep` dataclasses), so they can be
   serialized and verified by anyone holding just the root.
4. **Verification never raises on bad input.** `verify_proof` returns
   `False` for a tampered leaf, proof, or root instead of raising —
   verification is a question, not an exception path.

## Usage

```python
from merkle import MerkleTree

tree = MerkleTree([b"alpha", b"beta", b"gamma", b"delta"])
print(tree.root_hex)

proof = tree.proof(1)
assert MerkleTree.verify_proof(b"beta", proof, tree.root)
```

## CLI

```bash
pip install -e .
merkle build file1.txt file2.txt          # prints the root hash
merkle proof --index 2 file1.txt file2.txt # prints root + proof steps
merkle verify --leaf "hello" --root <hex> --proof "L:<hex>,R:<hex>"
```

Proof steps print one per line as `L:<hex>` (sibling on the left) or
`R:<hex>` (sibling on the right); `verify` accepts the same format,
comma-separated.

## Run tests

```bash
pip install pytest
python -m pytest -q
```

## Tech stack

Python 3.10+, standard library only (hashlib, argparse). No
dependencies.

## License

MIT
