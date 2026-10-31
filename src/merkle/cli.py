"""Command-line interface for the Merkle tree.

Usage:
    python -m merkle.cli build file1.txt file2.txt ...
    python -m merkle.cli proof --index 2 file1.txt file2.txt ...
    python -m merkle.cli verify --leaf "hello" --root <hex> --proof <hex,hex,...>

Proof steps are printed one per line as ``L:<hex>`` (sibling on the
left) or ``R:<hex>`` (sibling on the right). The ``verify`` command
accepts the same format, comma-separated.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from merkle import MerkleTree, ProofStep  # noqa: E402


def _read_items(paths: list[str]) -> list[bytes]:
    items: list[bytes] = []
    for path in paths:
        items.append(Path(path).read_bytes())
    return items


def _format_proof(proof: list[ProofStep]) -> str:
    return "\n".join(
        f"{'L' if step.sibling_is_left else 'R'}:{step.sibling.hex()}"
        for step in proof
    )


def _parse_proof(text: str) -> list[ProofStep]:
    steps: list[ProofStep] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        side, _, digest = part.partition(":")
        if side not in ("L", "R") or len(digest) != 64:
            raise ValueError(f"malformed proof step: {part!r}")
        steps.append(ProofStep(bytes.fromhex(digest), sibling_is_left=side == "L"))
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="merkle", description="Build and verify SHA-256 Merkle trees."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="print the root hash of files")
    p_build.add_argument("files", nargs="+", help="files to hash as leaves")

    p_proof = sub.add_parser("proof", help="print an inclusion proof")
    p_proof.add_argument("files", nargs="+", help="files to hash as leaves")
    p_proof.add_argument("--index", type=int, required=True, help="leaf index")

    p_verify = sub.add_parser("verify", help="verify an inclusion proof")
    p_verify.add_argument("--leaf", required=True, help="leaf data (text)")
    p_verify.add_argument("--root", required=True, help="expected root (hex)")
    p_verify.add_argument("--proof", required=True, help="proof steps, comma-separated")

    args = parser.parse_args(argv)

    if args.command == "build":
        print(MerkleTree(_read_items(args.files)).root_hex)
        return 0
    if args.command == "proof":
        tree = MerkleTree(_read_items(args.files))
        print(f"root: {tree.root_hex}")
        print(_format_proof(tree.proof(args.index)))
        return 0
    # verify
    try:
        proof = _parse_proof(args.proof)
        ok = MerkleTree.verify_proof(
            args.leaf, proof, bytes.fromhex(args.root)
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("valid" if ok else "invalid")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
