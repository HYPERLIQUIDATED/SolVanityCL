import json
import logging
from pathlib import Path
from typing import Set

from base58 import b58encode
from nacl.signing import SigningKey

# In-memory set of resolved file paths written this run. Keyed by path
# (not pubkey) so the same key targeted at different output dirs produces
# a file in each dir instead of silently skipping the second.
_seen_paths: Set[str] = set()


def get_public_key_from_private_bytes(pv_bytes: bytes) -> str:
    """
    Private key -> Public key (base58 encode)
    """
    pv = SigningKey(pv_bytes)
    pb_bytes = bytes(pv.verify_key)
    return b58encode(pb_bytes).decode()


def save_keypair(pv_bytes: bytes, output_dir: str, quiet: bool = False) -> str:
    """
    Save private key to JSON file, return public key.
    Deduplicates per resolved output path via in-memory set + file existence check.
    """
    if len(pv_bytes) != 32:
        logging.warning(f"Invalid private key length: {len(pv_bytes)} (expected 32)")
        return ""

    pv = SigningKey(pv_bytes)
    pb_bytes = bytes(pv.verify_key)
    pubkey = b58encode(pb_bytes).decode()

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    file_path = Path(output_dir) / f"{pubkey}.json"
    path_key = str(file_path.resolve())

    if path_key in _seen_paths:
        return pubkey
    _seen_paths.add(path_key)

    if file_path.exists():
        return pubkey

    file_path.write_text(json.dumps(list(pv_bytes + pb_bytes)))
    if not quiet:
        logging.info(f"Found: {pubkey}")
    return pubkey
