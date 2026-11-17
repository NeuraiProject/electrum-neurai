"""Chunked UTXO sets: the electrs-neurai extension described in its
doc/utxo-chunks.md ("utxo_chunks" in server.features).

An address whose history is too large for blockchain.scripthash.subscribe
(a mining pool's, an exchange's) is followed by its UTXOs instead: it is
subscribed with blockchain.scripthash.utxo_subscribe, and every new status
brings the changes since the block of the set we keep
(blockchain.scripthash.utxo_sync, in chunks of at most 128 KiB with
blockchain.scripthash.utxo_chunk).

Every chunk, the whole set and the number of UTXOs are checked against the
hashes and the count the server announces, so that a broken or mixed-up reply
is never kept. The UTXOs themselves are the server's word, as with
blockchain.scripthash.listunspent; their transactions are fetched (with their
txid checked) when they are spent.

A set is kept in the wallet file as a dict:
    'block_hash', 'height': the block of the set
    'set_hash': hash of the set (64 hex characters)
    'utxos': {'txid:n': [height, value, asset, is_coinbase]}
             (is_coinbase is None until it matters: see Synchronizer)
    'mempool_added': {'txid:n': [value, asset]}
    'mempool_spent': ['txid:n', ...]
    'status': what utxo_subscribe announces for it
"""

import asyncio
import hashlib
from typing import Dict, Iterable, List, Optional, Sequence, TYPE_CHECKING

from aiorpcx.jsonrpc import RPCError

if TYPE_CHECKING:
    from .interface import Interface

N = 2 ** 256
# Error of the server when the chunks of a reply are not kept anymore.
SNAPSHOT_EXPIRED = 10
# Chunks asked for without waiting for each reply.
CHUNKS_IN_FLIGHT = 8


class UtxoSetError(Exception):
    """A reply that doesn't add up: not kept."""


def utxo_hash(txid: str, vout: int, height: int, value: int, asset: Optional[str]) -> int:
    """SHA-256 of "txid:vout:height:value:asset", as a 256-bit integer."""
    text = f"{txid}:{vout}:{height}:{value}:{asset or ''}"
    return int.from_bytes(hashlib.sha256(text.encode()).digest(), 'big')


def to_hex(n: int) -> str:
    return format(n % N, '064x')


def _hash_of(outpoint: str, height: int, value: int, asset: Optional[str]) -> int:
    txid, vout = outpoint.split(':')
    return utxo_hash(txid, int(vout), height, value, asset)


def set_hash(utxos: Dict[str, list]) -> int:
    """Hash of a stored set of UTXOs ({'txid:n': [height, value, asset, ...]})."""
    return sum(_hash_of(o, u[0], u[1], u[2]) for o, u in utxos.items()) % N


def status(utxo_set: dict) -> str:
    """The utxo_subscribe status of a stored set: the hash of the spendable
    view (the set, plus the mempool's outputs, minus the mempool's spends)."""
    h = int(utxo_set['set_hash'], 16)
    for outpoint, (value, asset) in utxo_set['mempool_added'].items():
        h += _hash_of(outpoint, 0, value, asset)
    for outpoint in utxo_set['mempool_spent']:
        height, value, asset = utxo_set['utxos'][outpoint][:3]
        h -= _hash_of(outpoint, height, value, asset)
    return to_hex(h)


def _outpoint(entry: dict) -> str:
    return f"{entry['tx_hash']}:{entry['tx_pos']}"


def apply_changes(base: Dict[str, list], chunks: Sequence[dict], hashes: Sequence[int]) -> Dict[str, list]:
    """The set `base` after the `chunks` of a reply, each one checked against
    its hash. `base` is not changed."""
    if len(chunks) != len(hashes):
        raise UtxoSetError(f"{len(chunks)} chunks for {len(hashes)} hashes")
    utxos = dict(base)
    seen_added = False
    for i, (chunk, expected) in enumerate(zip(chunks, hashes)):
        h = 0
        if chunk['removed'] and seen_added:
            raise UtxoSetError("removed outpoints after added UTXOs")
        for entry in chunk['removed']:
            outpoint = _outpoint(entry)
            utxo = utxos.pop(outpoint, None)
            if utxo is None:
                raise UtxoSetError(f"removing {outpoint}, not in the set")
            h -= _hash_of(outpoint, utxo[0], utxo[1], utxo[2])
        for entry in chunk['added']:
            seen_added = True
            outpoint = _outpoint(entry)
            if outpoint in utxos:
                raise UtxoSetError(f"adding {outpoint} twice")
            if entry['height'] <= 0:
                raise UtxoSetError(f"unconfirmed UTXO {outpoint} in a chunk")
            utxos[outpoint] = [entry['height'], entry['value'], entry['asset'], None]
            h += _hash_of(outpoint, entry['height'], entry['value'], entry['asset'])
        if h % N != expected:
            raise UtxoSetError(f"chunk {i}: hash {to_hex(h)} instead of {to_hex(expected)}")
    return utxos


async def _get_chunks(interface: 'Interface', sh: str, reply_id: str, count: int) -> List[dict]:
    chunks = [None] * count  # type: List[Optional[dict]]
    semaphore = asyncio.Semaphore(CHUNKS_IN_FLIGHT)

    async def get(i):
        async with semaphore:
            chunks[i] = await interface.utxo_chunk(sh, reply_id, i)

    await asyncio.gather(*(get(i) for i in range(count)))
    return chunks


async def sync(interface: 'Interface', sh: str, stored: Optional[dict]) -> dict:
    """The set of `sh` after the changes since `stored` (from scratch when
    None), as a new dict to store. Raises UtxoSetError for a reply that
    doesn't add up."""
    for attempt in range(3):
        from_block = stored['block_hash'] if stored else None
        reply = await interface.utxo_sync(sh, from_block)
        hashes = [int(h, 16) for h in reply['chunks']]
        if reply['id'] is None:
            chunks = [{'added': reply['added'], 'removed': reply['removed']}]
        else:
            try:
                chunks = await _get_chunks(interface, sh, reply['id'], len(hashes))
            except RPCError as e:
                if e.code == SNAPSHOT_EXPIRED and attempt < 2:
                    continue  # ask again
                raise
        if reply['from_block'] is None:
            base, base_hash = {}, 0
        elif stored and reply['from_block'] == stored['block_hash']:
            base, base_hash = stored['utxos'], int(stored['set_hash'], 16)
        else:
            raise UtxoSetError(f"changes from {reply['from_block']}, asked from {from_block}")
        utxos = apply_changes(base, chunks, hashes)
        total = (base_hash + sum(hashes)) % N
        if total != int(reply['set_hash'], 16):
            raise UtxoSetError(f"set hash {to_hex(total)} instead of {reply['set_hash']}")
        if len(utxos) != reply['count']:
            raise UtxoSetError(f"{len(utxos)} UTXOs instead of {reply['count']}")
        mempool_added = {}
        for entry in reply['mempool']['added']:
            if entry['height'] != 0:
                raise UtxoSetError(f"mempool UTXO {_outpoint(entry)} at height {entry['height']}")
            mempool_added[_outpoint(entry)] = [entry['value'], entry['asset']]
        mempool_spent = [_outpoint(entry) for entry in reply['mempool']['spent']]
        for outpoint in mempool_spent:
            if outpoint not in utxos:
                raise UtxoSetError(f"the mempool spends {outpoint}, not in the set")
        result = {
            'block_hash': reply['block_hash'],
            'height': reply['height'],
            'set_hash': to_hex(total),
            'utxos': utxos,
            'mempool_added': mempool_added,
            'mempool_spent': mempool_spent,
        }
        result['status'] = status(result)
        return result
    raise UtxoSetError("the chunks of the reply kept expiring")


def txid_heights(utxo_sets: Iterable[dict]) -> Dict[str, int]:
    """Heights of the transactions of the UTXOs of `utxo_sets` (0: mempool)."""
    heights = {}
    for utxo_set in utxo_sets:
        for outpoint, utxo in utxo_set['utxos'].items():
            heights[outpoint.split(':')[0]] = utxo[0]
        for outpoint in utxo_set['mempool_added']:
            heights.setdefault(outpoint.split(':')[0], 0)
    return heights
