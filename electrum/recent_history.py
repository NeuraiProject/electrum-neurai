"""The last transactions of the addresses followed by their UTXOs: the
electrs-neurai extension blockchain.scripthash.get_recent_history described
in its doc/utxo-chunks.md ("recent_history" in server.features).

An address whose history is too large for the server is followed by its UTXOs
(utxo_sync.py): its balance and coins are complete, but it has no history.
The server keeps its last 1000 confirmed transactions (plus those in the
mempool), each one with what it changes in the balance of the address, and
sends them newest first, in pages. They are the server's word: no transaction
is downloaded to list them (one is fetched when the user opens it).

Every new status of such an address brings the first page, merged with what
is kept: normally it only adds the transactions of the new blocks. More pages
are asked for until they reach what is kept (or 1000 transactions), and the
whole list again after a reorg of the blocks it was read at.

The recent history of an address is kept in the wallet file as a dict:
    'height', 'block_hash': the tip the server read the entries at
    'complete': whether the entries are all the transactions of the address
    'status': the utxo_subscribe status they were read for
    'entries': [[txid, height, value, [[asset, amount], ...]], ...], newest
               first: those of the mempool (height 0, or -1 with unconfirmed
               inputs), then at most MAX_ENTRIES confirmed ones; `value` is the
               change in XNA satoshis (received minus spent), `amount` the
               change in an asset
"""

from typing import Callable, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .interface import Interface

# Error of the server for an address it has no recent history of (its
# history is not too large): the client keeps using get_history.
RECENT_HISTORY_UNAVAILABLE = 11
# Confirmed transactions kept per address, as many as the server keeps.
MAX_ENTRIES = 1000
# Entries asked for first (the new blocks bring a few), then per page (the
# server's maximum).
FIRST_PAGE = 50
PAGE = 500
# Pages read in one go at most: MAX_ENTRIES confirmed entries and a big mempool.
MAX_PAGES = 8


class RecentHistoryError(Exception):
    """Replies that don't add up: nothing is kept."""


class _Moved(Exception):
    """The server's tip or entries changed between two pages."""


class _Mismatch(Exception):
    """The entries kept don't match the server's ones."""


def entry_from_reply(entry: dict) -> list:
    """The stored form of an entry of a reply (checked by the interface)."""
    assets = sorted([asset, amount] for asset, amount in entry['assets'].items() if amount)
    return [entry['tx_hash'], entry['height'], entry['value'], assets]


def confirmed_entries(stored: Optional[dict]) -> List[list]:
    if stored is None:
        return []
    return [e for e in stored['entries'] if e[1] > 0]


def _no_progress(sent: int, answered: int) -> None:
    pass


async def _read(interface: 'Interface', sh: str, base: Optional[List[list]], base_height: int,
                progress: Callable[[int, int], None]) -> dict:
    """The entries of the server: from the start until they reach `base` (the
    confirmed entries kept, read at height `base_height`), all of them (up to
    MAX_ENTRIES confirmed ones) when `base` is None."""
    fetched = []  # type: List[list]
    offset, limit, first = 0, FIRST_PAGE, None
    reaches_base = False
    for _page in range(MAX_PAGES):
        progress(1, 0)
        reply = await interface.get_recent_history(sh, offset, limit)
        progress(0, 1)
        if first is None:
            first = reply
        elif (reply['height'], reply['block_hash'], reply['total']) != \
                (first['height'], first['block_hash'], first['total']):
            raise _Moved()
        fetched += [entry_from_reply(e) for e in reply['entries']]
        offset += len(reply['entries'])
        confirmed = [e for e in fetched if e[1] > 0]
        if offset >= reply['total'] or not reply['entries']:
            break  # all of them
        if base is not None and confirmed and confirmed[-1][1] <= base_height:
            reaches_base = True
            break
        if len(confirmed) >= MAX_ENTRIES:
            break
        limit = PAGE
    else:
        raise RecentHistoryError(f"more than {MAX_PAGES} pages")
    txids = [e[0] for e in fetched]
    if len(set(txids)) != len(txids):
        raise _Moved()  # an entry moved from a page to the next one
    mempool = [e for e in fetched if e[1] <= 0]
    confirmed = [e for e in fetched if e[1] > 0]
    if fetched[:len(mempool)] != mempool:
        raise RecentHistoryError("mempool entries after confirmed ones")
    if reaches_base:
        new = [e for e in confirmed if e[1] > base_height]
        old = confirmed[len(new):]
        # what the server still has of the blocks read before must be what we keep
        if old != base[:len(old)]:
            raise _Mismatch()
        entries = new + base
        # and it must not have more of them (e.g. kept fewer after a reorg)
        if min(first['total'] - len(mempool), MAX_ENTRIES) > len(entries[:MAX_ENTRIES]):
            raise _Mismatch()
    else:
        # all of the server's entries, or MAX_ENTRIES newer than those kept
        entries = confirmed
    return {
        'height': first['height'],
        'block_hash': first['block_hash'],
        'complete': first['complete'],
        'entries': mempool + entries[:MAX_ENTRIES],
    }


async def sync(interface: 'Interface', sh: str, stored: Optional[dict], *,
               is_in_chain: Callable[[int, str], bool],
               progress: Callable[[int, int], None] = _no_progress) -> dict:
    """The recent history of `sh` after the changes since `stored` (from
    scratch when None, or when its block is not in our chain anymore: a
    reorg), as a new dict to store (without 'status'). Raises
    RecentHistoryError for replies that don't add up, and RPCError for the
    server's errors (RECENT_HISTORY_UNAVAILABLE among them)."""
    base, base_height = None, 0
    if stored is not None and is_in_chain(stored['height'], stored['block_hash']):
        base, base_height = confirmed_entries(stored), stored['height']
    moves = 0
    while True:
        try:
            return await _read(interface, sh, base, base_height, progress)
        except _Moved:
            moves += 1  # read them again
            if moves >= 3:
                raise RecentHistoryError("the entries kept changing while they were read")
        except _Mismatch:
            base = None  # read them all


def heights(recent: dict) -> dict:
    """txid -> height of the entries of a stored recent history."""
    return {e[0]: e[1] for e in recent['entries']}
