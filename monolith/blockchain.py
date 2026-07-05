import os
import hashlib
from typing import List, Optional

try:
    from web3 import Web3
    from eth_account import Account
    HAS_WEB3 = True
except Exception:
    Web3 = None
    Account = None
    HAS_WEB3 = False


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def merkle_root(leaves: List[bytes]) -> str:
    """Compute a hex merkle root from a list of byte-leaves.

    Simple sha256-based merkle tree (non-optimized). Returns 0x-prefixed hex.
    """
    if not leaves:
        return '0x' + hashlib.sha256(b'').hexdigest()

    nodes = [ _sha256(l) for l in leaves ]

    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            a = nodes[i]
            b = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(_sha256(a + b))
        nodes = next_level

    return '0x' + nodes[0].hex()


def publish_merkle_root(leaves: List[bytes], private_key: str, rpc_url: Optional[str] = None, chain_id: int = 11155111) -> Optional[str]:
    """Publish merkle root to an Ethereum testnet by sending a zero-value tx with data field.

    - `leaves` : list of byte strings to include in the Merkle tree
    - `private_key` : hex private key string (0x...) for the sending account
    - `rpc_url` : optional RPC endpoint; prefers env `WEB3_RPC_URL`
    - `chain_id` : numeric chain id (default Sepolia = 11155111)

    Returns tx hash hex string on success, otherwise None.
    """
    if not HAS_WEB3:
        raise RuntimeError('web3.py or eth-account not installed')

    rpc = rpc_url or os.getenv('WEB3_RPC_URL')
    if not rpc:
        raise RuntimeError('No RPC URL configured; set WEB3_RPC_URL env var')

    w3 = Web3(Web3.HTTPProvider(rpc))
    acct = Account.from_key(private_key)

    root = merkle_root(leaves)
    data = bytes.fromhex(root[2:])

    nonce = w3.eth.get_transaction_count(acct.address)
    tx = {
        'to': '0x0000000000000000000000000000000000000000',
        'value': 0,
        'data': data,
        'gas': 21000,
        'nonce': nonce,
        'chainId': chain_id,
    }

    signed = Account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return w3.toHex(tx_hash)
