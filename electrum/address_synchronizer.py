# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import threading
import itertools
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple, NamedTuple, Sequence, List, Mapping, Union

from .crypto import sha256
from . import bitcoin, util
from .bitcoin import COINBASE_MATURITY
from .util import profiler, bfh, TxMinedInfo, UnrelatedTransactionException, with_lock, OldTaskGroup
from .transaction import Transaction, TxOutput, TxInput, PartialTxInput, TxOutpoint
from .synchronizer import Synchronizer
from .verifier import SPV
from .asset import get_asset_info_from_script, AssetMetadata, get_error_for_asset_typed, AssetType
from .blockchain import hash_header, Blockchain
from .i18n import _
from .logging import Logger
from .util import EventListener, event_listener
from .ipfs_db import IPFSDB
from .atomic_swap import AtomicSwap

if TYPE_CHECKING:
    from .network import Network
    from .wallet_db import WalletDB
    from .simple_config import SimpleConfig


TX_HEIGHT_FUTURE = -3
TX_HEIGHT_LOCAL = -2
TX_HEIGHT_UNCONF_PARENT = -1
TX_HEIGHT_UNCONFIRMED = 0

METADATA_VERIFIED = 1
METADATA_UNCONFIRMED = 0
METADATA_UNVERIFIED = -1

TX_TIMESTAMP_INF = 999_999_999_999
TX_HEIGHT_INF = 10 ** 9


class HistoryItem(NamedTuple):
    txid: str
    tx_mined_status: TxMinedInfo
    asset: Optional[str]
    delta: int
    fee: Optional[int]
    balance: int


class AddressSynchronizer(Logger, EventListener):
    """ address database """

    network: Optional['Network']
    asyncio_loop: Optional['asyncio.AbstractEventLoop'] = None
    synchronizer: Optional['Synchronizer']
    verifier: Optional['SPV']

    def __init__(self, db: 'WalletDB', config: 'SimpleConfig', *, name: str = None):
        self.db = db
        self.config = config
        self.name = name
        self.network = None
        Logger.__init__(self)
        # verifier (SPV) and synchronizer are started in start_network
        self.synchronizer = None
        self.verifier = None
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()
        self.future_tx = {}  # type: Dict[str, int]  # txid -> wanted (abs) height
        # Txs the server claims are mined but still pending verification:
        self.unverified_tx = defaultdict(int)  # type: Dict[str, int]  # txid -> height. Access with self.lock.
        # Txs the server claims are in the mempool:
        self.unconfirmed_tx = defaultdict(int)  # type: Dict[str, int]  # txid -> height. Access with self.lock.
        # thread local storage for caching stuff
        self.threadlocal_cache = threading.local()

        self.unverified_asset_metadata = {}  # type: Dict[str, Tuple[AssetMetadata, Tuple[TxOutpoint, int], Optional[Tuple[TxOutpoint, int]], Optional[Tuple[TxOutpoint, int]]]]
        self.unconfirmed_asset_metadata = {}  # type: Dict[str, Tuple[AssetMetadata, Tuple[TxOutpoint, int], Optional[Tuple[TxOutpoint, int]], Optional[Tuple[TxOutpoint, int]]]]

        self.unverified_tags_for_qualifier = defaultdict(dict)
        self.unconfirmed_tags_for_qualifier = defaultdict(dict)

        self.unverified_tags_for_h160 = defaultdict(dict)
        self.unconfirmed_tags_for_h160 = defaultdict(dict)

        self.unverified_verifier_for_restricted = defaultdict(dict)
        self.unconfirmed_verifier_for_restricted = defaultdict(dict)

        self.unverified_freeze_for_restricted = defaultdict(dict)
        self.unconfirmed_freeze_for_restricted = defaultdict(dict)

        self.unverified_broadcast = defaultdict(dict)
        self.unconfirmed_broadcast = defaultdict(dict)

        self._get_balance_cache = {}
        self._get_asset_balance_cache = {}
        self._get_assets_in_mempool_cache = {}

        self.load_and_cleanup()

    def diagnostic_name(self):
        return self.name or ""

    def with_transaction_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.transaction_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def load_and_cleanup(self):
        self.load_local_history()
        self.check_history()
        self.load_unverified_transactions()
        self.remove_local_transactions_we_dont_have()

    def is_mine(self, address: Optional[str]) -> bool:
        """Returns whether an address is in our set
        Note: This class has a larget set of addresses than the wallet
        """
        if not address: return False
        return self.db.is_addr_in_history(address)

    def get_addresses(self):
        return sorted(self.db.get_history())

    def get_assets_to_watch(self):
        return sorted(self.db.get_assets_to_watch())

    def get_broadcasts_to_watch(self):
        return sorted(self.db.get_broadcasts_to_watch())
    
    def add_broadcast_to_watch(self, asset):
        self.db.add_broadcast_to_watch(asset)
        if self.synchronizer:
            self.synchronizer.add_broadcast(asset)

    def remove_broadcast_to_watch(self, asset):
        with self.lock:
            for associated_data, _, _, tx_hash, _ in [x for x in self.get_broadcasts(asset)]:
                IPFSDB.get_instance().dissociate_asset_with_ipfs(associated_data, asset)
                self.db.remove_verified_broadcast(asset, tx_hash)
            self.db.remove_broadcast_to_watch(asset)

    def add_my_swap(self, swap: AtomicSwap):
        tx = Transaction(swap.swap_hex)
        id = tx.txid()
        assert id
        self.db.add_my_swap(id, swap)
        for input in tx.inputs():
            self.db.add_swap_id_for_outpoint(input.prevout, id)

    def get_address_history(self, addr: str) -> Dict[str, int]:
        """Returns the history for the address, as a txid->height dict.
        In addition to what we have from the server, this includes local and future txns.

        Also see related method db.get_addr_history, which stores the response from the server,
        so that only includes txns the server sees.
        """
        h = {}
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            related_txns = self._history_local.get(addr, set())
            for tx_hash in related_txns:
                tx_height = self.get_tx_height(tx_hash).height
                h[tx_hash] = tx_height
        return h

    def get_address_history_len(self, addr: str) -> int:
        """Return number of transactions where address is involved."""
        return len(self._history_local.get(addr, ()))

    def get_txin_address(self, txin: TxInput) -> Optional[str]:
        if txin.address:
            return txin.address
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        for addr in self.db.get_txo_addresses(prevout_hash):
            d = self.db.get_txo_addr(prevout_hash, addr)
            if prevout_n in d:
                return addr
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].address
        return None

    def get_txin_value(self, txin: TxInput, *, address: str = None, asset_aware = False) -> Optional[int]:
        if txin.value_sats() is not None:
            return txin.value_sats()
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        if address is None:
            address = self.get_txin_address(txin)
        if address:
            d = self.db.get_txo_addr(prevout_hash, address)
            try:
                v, asset, cb = d[prevout_n]
                if asset is not None and not asset_aware:
                    return 0
                return v
            except KeyError:
                pass
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].value
        return None

    def get_txin_scriptpubkey(self, txin: TxInput) -> Optional[bytes]:
        if txin.scriptpubkey is not None:
            return txin.scriptpubkey
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].scriptpubkey
        return None

    def load_unverified_transactions(self):
        # review transactions that are in the history
        for addr in self.db.get_history():
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_or_unconfirmed_tx(tx_hash, tx_height)

    def start_network(self, network: Optional['Network']) -> None:
        assert self.network is None, "already started"
        self.network = network
        if self.network is not None:
            self.synchronizer = Synchronizer(self)
            self.verifier = SPV(self.network, self)
            self.asyncio_loop = network.asyncio_loop
            self.register_callbacks()

    @event_listener
    def on_event_blockchain_updated(self, *args):
        self._get_balance_cache = {}  # invalidate cache
        self._get_asset_balance_cache = {}
        self._get_assets_in_mempool_cache = {}
        self.db.put('stored_height', self.get_local_height())

    async def stop(self):
        if self.network:
            try:
                async with OldTaskGroup() as group:
                    if self.synchronizer:
                        await group.spawn(self.synchronizer.stop())
                    if self.verifier:
                        await group.spawn(self.verifier.stop())
            finally:  # even if we get cancelled
                self.synchronizer = None
                self.verifier = None
                self.unregister_callbacks()

    def add_address(self, address):
        if address not in self.db.history:
            self.db.history[address] = []
        if self.synchronizer:
            self.synchronizer.add(address)
        self.up_to_date_changed()

    def get_conflicting_transactions(self, tx_hash, tx: Transaction, include_self=False):
        """Returns a set of transaction hashes from the wallet history that are
        directly conflicting with tx, i.e. they have common outpoints being
        spent with tx.

        include_self specifies whether the tx itself should be reported as a
        conflict (if already in wallet history)
        """
        conflicting_txns = set()
        with self.transaction_lock:
            for txin in tx.inputs():
                if txin.is_coinbase_input():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spending_tx_hash = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                if spending_tx_hash is None:
                    continue
                # this outpoint has already been spent, by spending_tx
                # annoying assert that has revealed several bugs over time:
                assert self.db.get_transaction(spending_tx_hash), f"spending tx {spending_tx_hash} not in wallet db"
                conflicting_txns |= {spending_tx_hash}
            if tx_hash in conflicting_txns:
                # this tx is already in history, so it conflicts with itself
                if len(conflicting_txns) > 1:
                    raise Exception('Found conflicting transactions already in wallet history.')
                if not include_self:
                    conflicting_txns -= {tx_hash}
            return conflicting_txns

    def get_transaction(self, txid: str) -> Optional[Transaction]:
        tx = self.db.get_transaction(txid)
        if tx:
            tx.deserialize()
            for txin in tx._inputs:
                tx_mined_info = self.get_tx_height(txin.prevout.txid.hex())
                txin.block_height = tx_mined_info.height  # not SPV-ed
                txin.block_txpos = tx_mined_info.txpos
        return tx

    def add_transaction(self, tx: Transaction, *, allow_unrelated=False, is_new=True) -> bool:
        """
        Returns whether the tx was successfully added to the wallet history.
        Note that a transaction may need to be added several times, if our
        list of addresses has increased. This will return True even if the
        transaction was already in self.db.
        """
        assert tx, tx
        # note: tx.is_complete() is not necessarily True; tx might be partial
        # but it *needs* to have a txid:
        tx_hash = tx.txid()
        if tx_hash is None:
            raise Exception("cannot add tx without txid to wallet history")
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            # NOTE: returning if tx in self.transactions might seem like a good idea
            # BUT we track is_mine inputs in a txn, and during subsequent calls
            # of add_transaction tx, we might learn of more-and-more inputs of
            # being is_mine, as we roll the gap_limit forward
            is_coinbase = tx.inputs()[0].is_coinbase_input()
            tx_height = self.get_tx_height(tx_hash).height
            if not allow_unrelated:
                # note that during sync, if the transactions are not properly sorted,
                # it could happen that we think tx is unrelated but actually one of the inputs is is_mine.
                # this is the main motivation for allow_unrelated
                is_mine = any([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()])
                is_for_me = any([self.is_mine(txo.address) for txo in tx.outputs()])
                if not is_mine and not is_for_me:
                    raise UnrelatedTransactionException()
            # Find all conflicting transactions.
            # In case of a conflict,
            #     1. confirmed > mempool > local
            #     2. this new txn has priority over existing ones
            # When this method exits, there must NOT be any conflict, so
            # either keep this txn and remove all conflicting (along with dependencies)
            #     or drop this txn
            conflicting_txns = self.get_conflicting_transactions(tx_hash, tx)
            if conflicting_txns:
                existing_mempool_txn = any(
                    self.get_tx_height(tx_hash2).height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT)
                    for tx_hash2 in conflicting_txns)
                existing_confirmed_txn = any(
                    self.get_tx_height(tx_hash2).height > 0
                    for tx_hash2 in conflicting_txns)
                if existing_confirmed_txn and tx_height <= 0:
                    # this is a non-confirmed tx that conflicts with confirmed txns; drop.
                    return False
                if existing_mempool_txn and tx_height == TX_HEIGHT_LOCAL:
                    # this is a local tx that conflicts with non-local txns; drop.
                    return False
                # keep this txn and remove all conflicting
                for tx_hash2 in conflicting_txns:
                    self.remove_transaction(tx_hash2)
            # add inputs
            def add_value_from_prev_output():
                # note: this takes linear time in num is_mine outputs of prev_tx
                addr = self.get_txin_address(txi)
                if addr and self.is_mine(addr):
                    outputs = self.db.get_txo_addr(prevout_hash, addr)
                    try:
                        v, asset, is_cb = outputs[prevout_n]
                    except KeyError:
                        pass
                    else:
                        self.db.add_txi_addr(tx_hash, addr, ser, v, asset)
                        self._get_balance_cache.clear()  # invalidate cache
                        self._get_asset_balance_cache.clear()
                        self._get_assets_in_mempool_cache.clear()
            for txi in tx.inputs():
                if txi.is_coinbase_input():
                    continue
                prevout_hash = txi.prevout.txid.hex()
                prevout_n = txi.prevout.out_idx
                ser = txi.prevout.to_str()
                self.db.set_spent_outpoint(prevout_hash, prevout_n, tx_hash)
                add_value_from_prev_output()
                self.db.remove_non_deterministic_txo_lockingscript(txi.prevout)
                swap_id = self.db.get_swap_id_for_outpoint(txi.prevout)
                if swap_id:
                    swap = self.db.get_swap_for_id(swap_id)
                    assert swap
                    swap.redeemed = True
                    util.trigger_callback('adb_swap_redeemed', self, swap_id)

            # add outputs
            for n, txo in enumerate(tx.outputs()):
                v = txo.value
                ser = tx_hash + ':%d'%n
                asset_data = get_asset_info_from_script(txo.scriptpubkey)
                scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                self.db.add_prevout_by_scripthash(scripthash, prevout=TxOutpoint.from_str(ser), value=asset_data.amount or v, asset=asset_data.asset)
                addr = txo.address
                if addr and self.is_mine(addr):
                    self.db.add_txo_addr(tx_hash, addr, n, asset_data.amount or v, asset_data.asset, is_coinbase)
                    self._get_balance_cache.clear()  # invalidate cache
                    self._get_asset_balance_cache.clear()
                    self._get_assets_in_mempool_cache.clear()
                    # give v to txi that spends me
                    next_tx = self.db.get_spent_outpoint(tx_hash, n)
                    if next_tx is not None:
                        self.db.add_txi_addr(next_tx, addr, ser, asset_data.amount or v, asset_data.asset)
                        self._add_tx_to_local_history(next_tx)
                    else:
                        if asset_data.asset:
                            self.watch_asset(asset_data.asset)
                        if not asset_data.is_deterministic():
                            outpoint = TxOutpoint(txid=bytes.fromhex(tx.txid()), out_idx=n)
                            if asset_data.well_formed_script:
                                self.logger.info(f'{outpoint.to_str()} is non-deterministic')
                            else:
                                self.logger.info(f'{outpoint.to_str()} is not well-formed')
                            self.db.add_non_deterministic_txo_lockingscript(outpoint)

            # add to local history
            self._add_tx_to_local_history(tx_hash)
            # save
            self.db.add_transaction(tx_hash, tx)
            self.db.add_num_inputs_to_tx(tx_hash, len(tx.inputs()))
            if is_new:
                util.trigger_callback('adb_added_tx', self, tx_hash, tx)
            return True

    def watch_asset(self, asset: str, restricted_check=False):
        if not self.db.is_watching_asset(asset):
            self.synchronizer.add_asset(asset)
            if not restricted_check:
                self.db.add_asset_to_watch(asset)
                if asset[0] == '$':
                    self.synchronizer.add_qualifier_for_tag(asset)
                    self.synchronizer.add_restricted_for_verifier(asset)
                    self.synchronizer.add_restricted_for_freeze(asset)
                elif asset[0] == '#':
                    self.synchronizer.add_qualifier_for_tag(asset)
            if asset[-1] == '!' and get_error_for_asset_typed(asset[:-1], AssetType.ROOT) is None:
                # Check for any restricted assets
                r_asset = f'${asset[:-1]}'
                self.watch_asset(r_asset, True)

    def remove_transaction(self, tx_hash: str) -> None:
        """Removes a transaction AND all its dependents/children
        from the wallet history.
        """
        with self.lock, self.transaction_lock:
            to_remove = {tx_hash}
            to_remove |= self.get_depending_transactions(tx_hash)
            for txid in to_remove:
                self._remove_transaction(txid)

    def _remove_transaction(self, tx_hash: str) -> None:
        """Removes a single transaction from the wallet history, and attempts
         to undo all effects of the tx (spending inputs, creating outputs, etc).
        """
        def maybe_update_atomic_swap(prevout: TxOutpoint):
            swap_id = self.db.get_swap_id_for_outpoint(prevout)
            if swap_id:
                swap = self.db.get_swap_for_id(swap_id)
                assert swap
                tx = Transaction(swap.swap_hex)
                for txin in tx.inputs():
                    if self.db.get_spent_outpoint(txin.prevout.txid.hex(), txin.prevout.out_idx): break
                else:
                    swap.redeemed = False
                    util.trigger_callback('adb_swap_unredeemed', self, swap_id)

        def remove_from_spent_outpoints():
            # undo spends in spent_outpoints
            if tx is not None:
                # if we have the tx, this branch is faster
                for txin in tx.inputs():
                    if txin.is_coinbase_input():
                        continue
                    prevout_hash = txin.prevout.txid.hex()
                    prevout_n = txin.prevout.out_idx
                    self.db.remove_spent_outpoint(prevout_hash, prevout_n)
                    maybe_update_atomic_swap(txin.prevout)
            else:
                # expensive but always works
                for prevout_hash, prevout_n in self.db.list_spent_outpoints():
                    spending_txid = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                    if spending_txid == tx_hash:
                        self.db.remove_spent_outpoint(prevout_hash, prevout_n)
                        maybe_update_atomic_swap(txin.prevout)

        with self.lock, self.transaction_lock:
            self.logger.info(f"removing tx from history {tx_hash}")
            tx = self.db.remove_transaction(tx_hash)
            remove_from_spent_outpoints()
            self._remove_tx_from_local_history(tx_hash)
            for addr in itertools.chain(self.db.get_txi_addresses(tx_hash), self.db.get_txo_addresses(tx_hash)):
                self._get_balance_cache.clear()  # invalidate cache
                self._get_asset_balance_cache.clear()
                self._get_assets_in_mempool_cache.clear()
            self.db.remove_txi(tx_hash)
            self.db.remove_txo(tx_hash)
            self.db.remove_tx_fee(tx_hash)
            self.db.remove_verified_tx(tx_hash)
            self.unverified_tx.pop(tx_hash, None)
            self.unconfirmed_tx.pop(tx_hash, None)
            if tx:
                for idx, txo in enumerate(tx.outputs()):
                    scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                    prevout = TxOutpoint(bfh(tx_hash), idx)
                    self.db.remove_prevout_by_scripthash(scripthash, prevout=prevout, value=txo.value)
        util.trigger_callback('adb_removed_tx', self, tx_hash, tx)

    def get_depending_transactions(self, tx_hash: str) -> Set[str]:
        """Returns all (grand-)children of tx_hash in this wallet."""
        with self.transaction_lock:
            children = set()
            for n in self.db.get_spent_outpoints(tx_hash):
                other_hash = self.db.get_spent_outpoint(tx_hash, n)
                children.add(other_hash)
                children |= self.get_depending_transactions(other_hash)
            return children

    def receive_tx_callback(self, tx_hash: str, tx: Transaction, tx_height: int) -> None:
        self.add_unverified_or_unconfirmed_tx(tx_hash, tx_height)
        self.add_transaction(tx, allow_unrelated=True)

    def receive_history_callback(self, addr: str, hist, tx_fees: Dict[str, int]):
        with self.lock:
            old_hist = self.get_address_history(addr)
            for tx_hash, height in old_hist.items():
                if (tx_hash, height) not in hist:
                    # make tx local
                    self.unverified_tx.pop(tx_hash, None)
                    self.unconfirmed_tx.pop(tx_hash, None)
                    self.db.remove_verified_tx(tx_hash)
                    if self.verifier:
                        self.verifier.remove_spv_proof_for_tx(tx_hash)
            self.db.set_addr_history(addr, hist)

        for tx_hash, tx_height in hist:
            # add it in case it was previously unconfirmed
            self.add_unverified_or_unconfirmed_tx(tx_hash, tx_height)
            # if addr is new, we have to recompute txi and txo
            tx = self.db.get_transaction(tx_hash)
            if tx is None:
                continue
            self.add_transaction(tx, allow_unrelated=True, is_new=False)
            # if we already had this tx, see if its height changed (e.g. local->unconfirmed)
            old_height = old_hist.get(tx_hash, None)
            if old_height is not None and old_height != tx_height:
                util.trigger_callback('adb_tx_height_changed', self, tx_hash, old_height, tx_height)

        # Store fees
        for tx_hash, fee_sat in tx_fees.items():
            self.db.add_tx_fee_from_server(tx_hash, fee_sat)

    @profiler
    def load_local_history(self):
        self._history_local = {}  # type: Dict[str, Set[str]]  # address -> set(txid)
        self._address_history_changed_events = defaultdict(asyncio.Event)  # address -> Event
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            self._add_tx_to_local_history(txid)

    @profiler
    def check_history(self):
        hist_addrs_mine = list(filter(lambda k: self.is_mine(k), self.db.get_history()))
        hist_addrs_not_mine = list(filter(lambda k: not self.is_mine(k), self.db.get_history()))
        for addr in hist_addrs_not_mine:
            self.db.remove_addr_history(addr)
        for addr in hist_addrs_mine:
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                if self.db.get_txi_addresses(tx_hash) or self.db.get_txo_addresses(tx_hash):
                    continue
                tx = self.db.get_transaction(tx_hash)
                if tx is not None:
                    self.add_transaction(tx, allow_unrelated=True)

    def remove_local_transactions_we_dont_have(self):
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            tx_height = self.get_tx_height(txid).height
            if tx_height == TX_HEIGHT_LOCAL and not self.db.get_transaction(txid):
                self.remove_transaction(txid)

    def clear_history(self):
        with self.lock:
            with self.transaction_lock:
                self.db.clear_history()
                self._history_local.clear()
                self._get_balance_cache.clear()  # invalidate cache
                self._get_asset_balance_cache.clear()
                self._get_assets_in_mempool_cache.clear()

    def _get_tx_sort_key(self, tx_hash: str) -> Tuple[int, int]:
        """Returns a key to be used for sorting txs."""
        with self.lock:
            tx_mined_info = self.get_tx_height(tx_hash)
            height = self.tx_height_to_sort_height(tx_mined_info.height)
            txpos = tx_mined_info.txpos or -1
            return height, txpos

    @classmethod
    def tx_height_to_sort_height(cls, height: int = None):
        """Return a height-like value to be used for sorting txs."""
        if height is not None:
            if height > 0:
                return height
            if height == TX_HEIGHT_UNCONFIRMED:
                return TX_HEIGHT_INF
            if height == TX_HEIGHT_UNCONF_PARENT:
                return TX_HEIGHT_INF + 1
            if height == TX_HEIGHT_FUTURE:
                return TX_HEIGHT_INF + 2
            if height == TX_HEIGHT_LOCAL:
                return TX_HEIGHT_INF + 3
        return TX_HEIGHT_INF + 100

    def with_local_height_cached(func):
        # get local height only once, as it's relatively expensive.
        # take care that nested calls work as expected
        def f(self, *args, **kwargs):
            orig_val = getattr(self.threadlocal_cache, 'local_height', None)
            self.threadlocal_cache.local_height = orig_val or self.get_local_height()
            try:
                return func(self, *args, **kwargs)
            finally:
                self.threadlocal_cache.local_height = orig_val
        return f

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_history(self, domain) -> Sequence[HistoryItem]:
        domain = set(domain)
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(lambda: defaultdict(int))  # type: Dict[str, Dict[Optional[str], int]]
        for addr in domain:
            h = self.get_address_history(addr).items()
            for tx_hash, height in h:
                for asset, value in self.get_tx_delta(tx_hash, addr).items():
                    tx_deltas[tx_hash][asset] += value
        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            tx_mined_status = self.get_tx_height(tx_hash)
            fee = self.get_tx_fee(tx_hash)
            for _asset, delta in tx_deltas[tx_hash].items():
                history.append((tx_hash, tx_mined_status, _asset, delta, fee))
        history.sort(key = lambda x: self._get_tx_sort_key(x[0]))
        # 3. add balance
        h2 = []
        balance = defaultdict(int)
        for tx_hash, tx_mined_status, asset, delta, fee in history:
            balance[asset] += delta
            h2.append(HistoryItem(
                txid=tx_hash,
                tx_mined_status=tx_mined_status,
                asset=asset,
                delta=delta,
                fee=fee,
                balance=balance[asset]))
        # sanity check
        asset_balances = self.get_balance(domain, asset_aware=True)
        for key, _balance in balance.items():
            c, u, x = asset_balances[key]
            if _balance != c + u + x:
                self.logger.error(f'sanity check failed! key={key}; c={c},u={u},x={x} while history balance={_balance}')
                raise Exception("wallet.get_history() failed balance sanity-check")
        return h2

    def _add_tx_to_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                cur_hist.add(txid)
                self._history_local[addr] = cur_hist
                self._mark_address_history_changed(addr)

    def _remove_tx_from_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                try:
                    cur_hist.remove(txid)
                except KeyError:
                    pass
                else:
                    self._history_local[addr] = cur_hist
                    self._mark_address_history_changed(addr)

    def _mark_address_history_changed(self, addr: str) -> None:
        def set_and_clear():
            event = self._address_history_changed_events[addr]
            # history for this address changed, wake up coroutines:
            event.set()
            # clear event immediately so that coroutines can wait() for the next change:
            event.clear()
        if self.asyncio_loop:
            self.asyncio_loop.call_soon_threadsafe(set_and_clear)

    async def wait_for_address_history_to_change(self, addr: str) -> None:
        """Wait until the server tells us about a new transaction related to addr.

        Unconfirmed and confirmed transactions are not distinguished, and so e.g. SPV
        is not taken into account.
        """
        assert self.is_mine(addr), "address needs to be is_mine to be watched"
        await self._address_history_changed_events[addr].wait()

    def add_unverified_or_unconfirmed_tx(self, tx_hash, tx_height):
        if self.db.is_in_verified_tx(tx_hash):
            if tx_height <= 0:
                # tx was previously SPV-verified but now in mempool (probably reorg)
                with self.lock:
                    self.db.remove_verified_tx(tx_hash)
                    self.unconfirmed_tx[tx_hash] = tx_height
                if self.verifier:
                    self.verifier.remove_spv_proof_for_tx(tx_hash)
        else:
            with self.lock:
                if tx_height > 0:
                    self.unverified_tx[tx_hash] = tx_height
                else:
                    self.unconfirmed_tx[tx_hash] = tx_height

    def add_unverified_or_unconfirmed_asset_metadata(self, asset, d):
        metadata = AssetMetadata(
            sats_in_circulation=d['sats_in_circulation'],
            divisions = d['divisions'],
            reissuable = d['reissuable'],
            associated_data = d['ipfs'] if d['has_ipfs'] else None
        )

        source_outpoint = TxOutpoint(txid=bytes.fromhex(d['source']['tx_hash']), out_idx=d['source']['tx_pos'])
        source_height = d['source']['height']

        source = source_outpoint, source_height

        source_divisions = None

        if 'source_divisions' in d:
            _source_outpoint = TxOutpoint(txid=bytes.fromhex(d['source_divisions']['tx_hash']), out_idx=d['source_divisions']['tx_pos'])
            _source_height = d['source_divisions']['height']
            source_divisions = _source_outpoint, _source_height

        source_ipfs = None

        if 'source_ipfs' in d:
            __source_outpoint = TxOutpoint(txid=bytes.fromhex(d['source_ipfs']['tx_hash']), out_idx=d['source_ipfs']['tx_pos'])
            __source_height = d['source_ipfs']['height']
            source_ipfs = __source_outpoint, __source_height

        with self.lock:
            self.unconfirmed_asset_metadata.pop(asset, None)
            self.unverified_asset_metadata.pop(asset, None)
            if source_height > 0:
                self.unverified_asset_metadata[asset] = metadata, source, source_divisions, source_ipfs
            else:
                self.unconfirmed_asset_metadata[asset] = metadata, source, source_divisions, source_ipfs
                util.trigger_callback('adb_added_unconfirmed_asset_metadata', self, asset)

    def get_unverified_asset_metadatas(self):
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return dict(self.unverified_asset_metadata)  # copy

    def remove_unverified_asset_metadata(self, asset: str, source_height: int):
        with self.lock:
            maybe_metadata = self.unverified_asset_metadata.get(asset, None)
            if maybe_metadata:
                current_height = maybe_metadata[1][1]
                if current_height == source_height:
                    self.unverified_asset_metadata.pop(asset, None)

    def add_verified_asset_metadata(self, asset: str, metadata: AssetMetadata, source_tup, source_divisions_tup, source_associated_data_tup):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_asset_metadata.pop(asset, None)
            old_metadata = self.db.get_verified_asset_metadata(asset)
            if old_metadata:
                if old_metadata.is_associated_data_ipfs():
                    old_ipfs_str = old_metadata.associated_data_as_ipfs()
                    util.trigger_callback('ipfs_hash_dissociate_asset', old_ipfs_str, asset)
            self.db.add_verified_asset_metadata(asset, metadata, source_tup, source_divisions_tup, source_associated_data_tup)
        util.trigger_callback('adb_added_verified_asset_metadata', self, asset)

    def get_metadata_for_synchronizer(self, asset: str) -> Optional[AssetMetadata]:
        with self.lock:
            unconfirmed = self.unconfirmed_asset_metadata.get(asset, None)
            if unconfirmed:
                return unconfirmed[0]
            unverified = self.unverified_asset_metadata.get(asset, None)
            if unverified:
                return unverified[0]
            verified = self.db.get_verified_asset_metadata(asset)
            if verified:
                return verified
            return None
    
    def get_asset_metadata(self, asset: str) -> Optional[Tuple[AssetMetadata, int]]:
        with self.lock:
            unconfirmed = self.unconfirmed_asset_metadata.get(asset, None)
            if unconfirmed and self.config.HANDLE_UNCONFIRMED_METADATA:
                return unconfirmed[0], METADATA_UNCONFIRMED
            verified = self.db.get_verified_asset_metadata(asset)
            if verified:
                return verified, METADATA_VERIFIED
            unverified = self.unverified_asset_metadata.get(asset, None)
            if unverified:
                return unverified[0], METADATA_UNVERIFIED
            return None
    
    def get_asset_metadata_txids(self, asset: str) -> Optional[Tuple[bytes, Optional[bytes], Optional[bytes]]]:
        with self.lock:
            unconfirmed = self.unconfirmed_asset_metadata.get(asset, None)
            if unconfirmed and self.config.HANDLE_UNCONFIRMED_METADATA:
                # source_main, div, ipfs
                return (
                    unconfirmed[1][0].txid, 
                    unconfirmed[2][0].txid if unconfirmed[2] else None, 
                    unconfirmed[3][0].txid if unconfirmed[3] else None
                )
            verified = self.db.get_verified_asset_metadata_source_txids(asset)
            if verified:
                return verified
            unverified = self.unverified_asset_metadata.get(asset, None)
            if unverified:
                return (
                    unverified[1][0].txid, 
                    unverified[2][0].txid if unverified[2] else None, 
                    unverified[3][0].txid if unverified[3] else None
                )
            return None
        
    def get_asset_metadata_outpoint(self, asset: str) -> Optional[TxOutpoint]:
        with self.lock:
            base_source = self.db.get_verified_asset_metadata_base_source(asset)
            if base_source:
                return base_source[0]
            unconfirmed = self.unconfirmed_asset_metadata.get(asset, None)
            if unconfirmed:
                return unconfirmed[1][0]
            unverified = self.unverified_asset_metadata.get(asset, None)
            if unverified:
                return unverified[1][0]
            return None

    def add_unverified_or_unconfirmed_verifier_string_for_restricted(self, asset: str, data):
        with self.lock:
            self.unconfirmed_verifier_for_restricted.pop(asset, None)
            self.unverified_verifier_for_restricted.pop(asset, None)
            if data['height'] > 0:
                self.unverified_verifier_for_restricted[asset] = data
            else:
                self.unconfirmed_verifier_for_restricted[asset] = data

    def get_restricted_verifier_string_for_synchronizer(self, asset: str) -> Dict[str, object]:
        with self.lock:
            unconfirmed = self.unconfirmed_verifier_for_restricted.get(asset, dict())
            if unconfirmed:
                return unconfirmed
            unverified = self.unverified_verifier_for_restricted.get(asset, dict())
            if unverified:
                return unverified
            return self.db.get_verified_restricted_verifier(asset) or {}

    def get_restricted_verifier_string(self, asset: str) -> Optional[Tuple[dict, int]]:
        with self.lock:
            unconfirmed = self.unconfirmed_verifier_for_restricted.get(asset, dict())
            if unconfirmed and self.config.HANDLE_UNCONFIRMED_METADATA:
                return unconfirmed, METADATA_UNCONFIRMED
            verified = self.db.get_verified_restricted_verifier(asset)
            if verified:
                return verified, METADATA_VERIFIED
            unverified = self.unverified_verifier_for_restricted.get(asset, dict())
            if unverified:
                return unverified, METADATA_UNVERIFIED
        return None

    def get_unverified_restricted_verifier_strings(self) -> Dict[str, Dict[str, object]]:
        with self.lock:
            return dict(self.unverified_verifier_for_restricted)

    def remove_unverified_restricted_verifier_string(self, asset: str, source_height: int):
        with self.lock:
            d = self.unverified_verifier_for_restricted.get(asset, dict())
            if d and d['height'] == source_height:
                self.unverified_verifier_for_restricted.pop(asset)

    def add_verified_restricted_verifier_string(self, asset: str, d):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_verifier_for_restricted.pop(asset, None)
            self.db.add_verified_restricted_verifier(asset, d)
        util.trigger_callback('adb_added_verified_restricted_verifier', self, asset, d['string'])

    def add_unverified_or_unconfirmed_broadcasts(self, asset: str, tx_map: Dict):
        with self.lock:
            self.unconfirmed_broadcast.pop(asset, None)
            self.unverified_broadcast.pop(asset, None)

            verified = self.db.get_verified_broadcasts(asset)

            for tx_hash, d in tx_map.items():
                if d['height'] > 0:
                    if d == verified.get(tx_hash, None): continue
                    self.unverified_broadcast[asset][tx_hash] = d
                else:
                    self.unconfirmed_broadcast[asset][tx_hash] = d
                    util.trigger_callback('adb_added_unconfirmed_broadcast', self, asset, tx_hash)

    def get_broadcasts_for_synchronizer(self, asset: str) -> Dict[str, Dict[str, object]]:
        with self.lock:
            d = self.db.get_verified_broadcasts(asset)
            d.update(self.unverified_broadcast.get(asset, dict()))
            d.update(self.unconfirmed_broadcast.get(asset, dict()))
            return [{'tx_hash': tx_hash, **d_i} for tx_hash, d_i in d.items()]

    def get_broadcasts(self, asset: str) -> Sequence[Tuple[str, int, int, str, int]]:
        with self.lock:
            combined = {}
            combined.update(self.db.get_verified_broadcasts(asset))
            combined.update(self.unverified_broadcast.get(asset, dict()))
            if self.config.HANDLE_UNCONFIRMED_METADATA:
                combined.update(self.unconfirmed_broadcast.get(asset, dict()))

            def mempool_key(tup):
                if tup[2] < 0:
                    return -1
                else:
                    return 1

            result = [(d['data'], d['expiration'], d['height'], tx_hash, d['tx_pos']) for tx_hash, d in combined.items()]
            result.sort(key=lambda x: x[2], reverse=True)
            return sorted(result, key=mempool_key)

    def get_unverified_broadcasts(self) -> Dict[str, Dict[str, object]]:
        with self.lock:
            return {k: dict(v) for k, v in self.unverified_broadcast.items()}

    def remove_unverified_broadcast(self, asset: str, tx_hash: str, source_height: int):
        with self.lock:
            d1 = self.unverified_broadcast.get(asset, dict())
            d2 = d1.get(tx_hash, dict())
            if d2 and d2['height'] == source_height:
                self.unverified_broadcast.get(asset, dict()).pop(tx_hash, None)
                if not self.unverified_broadcast.get(asset, None):
                    self.unverified_broadcast.pop(asset, None)

    def add_verified_broadcast(self, asset: str, tx_hash: str, data: Dict):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_broadcast.get(asset, dict()).pop(tx_hash, None)
            if not self.unverified_broadcast.get(asset, None):
                self.unverified_broadcast.pop(asset, None)
            self.db.add_verified_broadcast(asset, tx_hash, data)
        util.trigger_callback('adb_added_verified_broadcast', self, asset, tx_hash)

    def add_unverified_or_unconfirmed_freeze_for_restricted(self, asset: str, data):
        with self.lock:
            self.unconfirmed_freeze_for_restricted.pop(asset, None)
            self.unverified_freeze_for_restricted.pop(asset, None)
            if data['height'] > 0:
                self.unverified_freeze_for_restricted[asset] = data
            else:
                self.unconfirmed_freeze_for_restricted[asset] = data

    def get_restricted_freeze_for_synchronizer(self, asset: str) -> Dict[str, object]:
        with self.lock:
            unconfirmed = self.unconfirmed_freeze_for_restricted.get(asset, dict())
            if unconfirmed:
                return unconfirmed
            unverified = self.unverified_freeze_for_restricted.get(asset, dict())
            if unverified:
                return unverified
            return self.db.get_verified_restricted_freeze(asset) or {}

    def get_restricted_freeze(self, asset: str) -> Optional[Tuple[dict, int]]:
        with self.lock:
            unconfirmed = self.unconfirmed_freeze_for_restricted.get(asset, dict())
            if unconfirmed and self.config.HANDLE_UNCONFIRMED_METADATA:
                return unconfirmed, METADATA_UNCONFIRMED
            verified = self.db.get_verified_restricted_freeze(asset)
            if verified:
                return verified, METADATA_VERIFIED
            unverified = self.unverified_freeze_for_restricted.get(asset, dict())
            if unverified:
                return unverified, METADATA_UNVERIFIED
        return None

    def get_unverified_restricted_freezes(self) -> Dict[str, Dict[str, object]]:
        with self.lock:
            return dict(self.unverified_freeze_for_restricted)

    def remove_unverified_restricted_freeze(self, asset: str, source_height: int):
        with self.lock:
            d = self.unverified_freeze_for_restricted.get(asset, dict())
            if d and d['height'] == source_height:
                self.unverified_freeze_for_restricted.pop(asset, None)

    def add_verified_restricted_freeze(self, asset: str, d):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_freeze_for_restricted.pop(asset, None)
            self.db.add_verified_restricted_freeze(asset, d)
        util.trigger_callback('adb_added_verified_restricted_freeze', self, asset, d['frozen'])

    def add_unverified_or_unconfirmed_tags_for_h160(self, h160, asset_tags):
        verified_h160_tags = self.db.get_verified_h160_tags(h160)
        if not verified_h160_tags:
            verified_h160_tags = dict()
        with self.lock:
            self.unconfirmed_tags_for_h160.pop(h160, None)
            self.unverified_tags_for_h160.pop(h160, None)
            for asset, d in asset_tags.items():
                if d['height'] > 0:
                    verified_asset_tags = self.db.get_verified_qualifier_tags(asset)
                    if verified_asset_tags and h160 in verified_asset_tags and verified_asset_tags[h160] == d:
                        # We have already verified this tag
                        self.db.add_verified_h160_tag(h160, asset, d)
                        continue
                    if asset in verified_h160_tags:
                        if verified_h160_tags[asset] == d:
                            # no change with what we know
                            continue
                    self.unverified_tags_for_h160[h160][asset] = d
                else:
                    self.unconfirmed_tags_for_h160[h160][asset] = d

    def get_h160_tags_for_synchronizer(self, h160: str) -> Dict[str, Dict[str, object]]:
        with self.lock:
            tags = self.db.get_verified_h160_tags(h160)
            if not tags:
                tags = {}
            unverified_tags = self.unverified_tags_for_h160.get(h160)
            if unverified_tags:
                for h160, d in unverified_tags.items():
                    tags[h160] = d
            unconfirmed_tags = self.unconfirmed_tags_for_h160.get(h160)
            if unconfirmed_tags:
                for h160, d in unconfirmed_tags.items():
                    tags[h160] = d
            return tags

    def is_h160_tagged(self, h160: str, asset: str) -> Optional[bool]:
        with self.lock:
            #unconfirmed_tags = self.unconfirmed_tags_for_h160.get(h160)
            #if unconfirmed_tags and asset in unconfirmed_tags:
            #    return unconfirmed_tags[asset]['flag']
            #unconfirmed_tags = self.unconfirmed_tags_for_qualifier.get(asset)
            #if unconfirmed_tags and h160 in unconfirmed_tags:
            #    return unconfirmed_tags[h160]['flag']
            unverified_tags = self.unverified_tags_for_h160.get(h160)
            if unverified_tags and asset in unverified_tags:
                return unverified_tags[asset]['flag']
            unverified_tags = self.unverified_tags_for_qualifier.get(asset)
            if unverified_tags and h160 in unverified_tags:
                return unverified_tags[h160]['flag']
            tag = self.db.get_verified_h160_tag(h160, asset)
            if tag:
                return tag['flag']
            if self.db.is_h160_checked(h160):
                return False
            tag = self.db.get_verified_qualifier_tag(asset, h160)
            if tag:
                return tag['flag']
            if self.db.is_qualified_checked(asset):
                return False
        return None

    def get_unverified_tags_for_h160(self) -> Dict[str, Dict[str, Dict[str, object]]]:
        with self.lock:
            return dict(self.unverified_tags_for_h160)

    def remove_unverified_tag_for_h160(self, h160: str, asset: str, source_height: int):
        with self.lock:
            maybe_tags = self.unverified_tags_for_h160.get(h160)
            if maybe_tags:
                maybe_tag = maybe_tags.get(asset)
                if maybe_tag:
                    if maybe_tag['height'] == source_height:
                        self.unverified_tags_for_h160[h160].pop(asset, None)
                        if not self.unverified_tags_for_h160[h160]:
                            self.unverified_tags_for_h160.pop(h160, None)

    def add_verified_tag_for_h160(self, h160: str, asset: str, d):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tags_for_h160.get(h160, dict()).pop(asset, None)
            if not self.unverified_tags_for_h160.get(h160):
                self.unverified_tags_for_h160.pop(h160, None)
            self.db.add_verified_h160_tag(h160, asset, d)
        util.trigger_callback('adb_added_verified_tag_for_h160', self, h160, asset)

    def add_unverified_or_unconfirmed_tags_for_qualifier(self, asset, h160_tags):
        verified_tags = self.db.get_verified_qualifier_tags(asset)
        if not verified_tags:
            verified_tags = dict()
        with self.lock:
            self.unconfirmed_tags_for_qualifier.pop(asset, None)
            self.unverified_tags_for_qualifier.pop(asset, None)
            for h160, d in h160_tags.items():
                if d['height'] > 0:
                    verified_h160_tags = self.db.get_verified_h160_tags(h160)
                    if verified_h160_tags and asset in verified_h160_tags and verified_h160_tags[asset] == d:
                        # We have already verified this tag
                        self.db.add_verified_qualifier_tag(asset, h160, d)
                        continue
                    if h160 in verified_tags:
                        if (verified_tags[h160]['tx_hash'], verified_tags[h160]['height']) == (d['tx_hash'], d['height']):
                            # no change with what we know
                            continue
                    self.unverified_tags_for_qualifier[asset][h160] = d
                else:
                    self.unconfirmed_tags_for_qualifier[asset][h160] = d

    def get_qualifier_tags_for_synchronizer(self, asset: str) -> Dict[str, Dict[str, object]]:
        with self.lock:
            tags = self.db.get_verified_qualifier_tags(asset)
            if not tags:
                tags = {}
            unverified_tags = self.unverified_tags_for_qualifier.get(asset)
            if unverified_tags:
                for h160, d in unverified_tags.items():
                    tags[h160] = d
            unconfirmed_tags = self.unconfirmed_tags_for_qualifier.get(asset)
            if unconfirmed_tags:
                for h160, d in unconfirmed_tags.items():
                    tags[h160] = d
            return tags

    def get_unverified_tags_for_qualifier(self) -> Dict[str, Dict[str, Dict[str, object]]]:
        with self.lock:
            return dict(self.unverified_tags_for_qualifier)

    def remove_unverified_tag_for_qualifier(self, asset: str, h160: str, source_height: int):
        with self.lock:
            maybe_tags = self.unverified_tags_for_qualifier.get(asset)
            if maybe_tags:
                maybe_tag = maybe_tags.get(h160)
                if maybe_tag:
                    if maybe_tag['height'] == source_height:
                        self.unverified_tags_for_qualifier[asset].pop(h160, None)
                        if not self.unverified_tags_for_qualifier[asset]:
                            self.unverified_tags_for_qualifier.pop(asset, None)

    def add_verified_tag_for_qualifier(self, asset: str, h160: str, d):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tags_for_qualifier.get(asset, dict()).pop(h160, None)
            if not self.unverified_tags_for_qualifier.get(asset):
                self.unverified_tags_for_qualifier.pop(asset, None)
            self.db.add_verified_qualifier_tag(asset, h160, d)
        util.trigger_callback('adb_added_verified_tag_for_qualifier', self, asset, h160)

    def get_tags_for_qualifier(self, asset: str, *, include_mempool=True):
        with self.lock:
            d = {}
            for h160, data in (self.db.get_verified_qualifier_tags(asset) or dict()).items():
                data['type'] = METADATA_VERIFIED
                d[h160] = data
            for h160, data in self.unverified_tags_for_qualifier.get(asset, dict()).items():
                data['type'] = METADATA_UNVERIFIED
                d[h160] = data
            if include_mempool and self.config.HANDLE_UNCONFIRMED_METADATA:
                for h160, data in self.unconfirmed_tags_for_qualifier.get(asset, dict()).items():
                    data['type'] = METADATA_UNCONFIRMED
                    d[h160] = data
            return d

    def get_tags_for_h160(self, h160: str, *, include_mempool=True) -> Dict[str, Dict]:
        with self.lock:
            d = {}
            for asset, data in (self.db.get_verified_h160_tags(h160) or dict()).items():
                data['type'] = METADATA_VERIFIED
                d[asset] = data
            for asset, data in self.unverified_tags_for_h160.get(h160, dict()).items():
                data['type'] = METADATA_UNVERIFIED
                d[asset] = data
            if include_mempool and self.config.HANDLE_UNCONFIRMED_METADATA:
                for asset, data in self.unconfirmed_tags_for_h160.get(h160, dict()).items():
                    data['type'] = METADATA_UNCONFIRMED
                    d[asset] = data
            return d

    def remove_unverified_tx(self, tx_hash, tx_height):
        with self.lock:
            new_height = self.unverified_tx.get(tx_hash)
            if new_height == tx_height:
                self.unverified_tx.pop(tx_hash, None)

    def add_verified_tx(self, tx_hash: str, info: TxMinedInfo):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tx.pop(tx_hash, None)
            self.db.add_verified_tx(tx_hash, info)
        util.trigger_callback('adb_added_verified_tx', self, tx_hash)

    def get_unverified_txs(self) -> Dict[str, int]:
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return dict(self.unverified_tx)  # copy

    def undo_verifications(self, blockchain: Blockchain, above_height: int) -> Set[str]:
        '''Used by the verifier when a reorg has happened'''
        txs = set()
        assets = set()
        with self.lock:
            for asset in self.db.get_assets_verified_after_height(above_height):
                base_outpoint, base_height = self.db.get_verified_asset_metadata_base_source(asset)
                verified_info = self.db.get_verified_tx(base_outpoint.txid.hex())
                header = blockchain.read_header(base_height)
                if header and verified_info and hash_header(header) == verified_info.header_hash: continue
                assets.add(asset)
                tup = self.db.remove_verified_asset_metadata(asset)
                self.unverified_asset_metadata[asset] = tup
                _, (outpoint, _), div_tup, associated_data_tup = tup
                txs.add(outpoint.txid.hex())
                if div_tup:
                    txs.add(div_tup[0].txid.hex())
                if associated_data_tup:
                    txs.add(associated_data_tup[0].txid.hex())
            for asset in self.db.get_verified_restricted_verifier_after_height(above_height):
                data = self.db.get_verified_restricted_verifier(asset)
                verified_info = self.db.get_verified_tx(data['tx_hash'])
                header = blockchain.read_header(data['height'])
                if header and verified_info and hash_header(header) == verified_info.header_hash: continue
                
                self.db.remove_verified_restricted_verifier(asset)
                txs.add(data['tx_hash'])
            for asset in self.db.get_verified_restricted_freezes_after_height(above_height):
                data = self.db.get_verified_restricted_freeze(asset)
                verified_info = self.db.get_verified_tx(data['tx_hash'])
                header = blockchain.read_header(data['height'])
                if header and verified_info and hash_header(header) == verified_info.header_hash: continue
                
                self.db.remove_verified_restricted_freeze(asset)
                txs.add(data['tx_hash'])
            for asset, h160s in self.db.get_verified_qualifier_tags_after_height(above_height).items():
                for h160 in h160s:
                    tag_data = self.db.get_verified_qualifier_tag(asset, h160)
                    verified_info = self.db.get_verified_tx(tag_data['tx_hash'])
                    header = blockchain.read_header(tag_data['height'])
                    if header and verified_info and hash_header(header) == verified_info.header_hash: continue
                    
                    self.db.remove_verified_qualifier_tag(asset, h160)
                    txs.add(tag_data['tx_hash'])
            for h160, assets in self.db.get_verified_h160_tags_after_height(above_height).items():
                for asset in assets:
                    tag_data = self.db.get_verified_h160_tag(h160, asset)
                    verified_info = self.db.get_verified_tx(tag_data['tx_hash'])
                    header = blockchain.read_header(tag_data['height'])
                    if header and verified_info and hash_header(header) == verified_info.header_hash: continue
                    
                    self.db.remove_verified_h160_tag(h160, asset)
                    txs.add(tag_data['tx_hash'])
            for asset, tx_hashes in self.db.get_verified_broadcasts_after_height(above_height).items():
                for tx_hash in tx_hashes:
                    broadcast = self.db.get_verified_broadcast(asset, tx_hash)
                    verified_info = self.db.get_verified_tx(tx_hash)
                    header = blockchain.read_header(broadcast['height'])
                    if header and verified_info and hash_header(header) == verified_info.header_hash: continue

                    self.db.remove_verified_broadcast(asset, tx_hash)
                    txs.add(tx_hash)
            for tx_hash in self.db.list_verified_tx():
                info = self.db.get_verified_tx(tx_hash)
                tx_height = info.height
                if tx_height > above_height:
                    header = blockchain.read_header(tx_height)
                    if not header or hash_header(header) != info.header_hash:
                        self.db.remove_verified_tx(tx_hash)
                        # NOTE: we should add these txns to self.unverified_tx,
                        # but with what height?
                        # If on the new fork after the reorg, the txn is at the
                        # same height, we will not get a status update for the
                        # address. If the txn is not mined or at a diff height,
                        # we should get a status update. Unless we put tx into
                        # unverified_tx, it will turn into local. So we put it
                        # into unverified_tx with the old height, and if we get
                        # a status update, that will overwrite it.
                        self.unverified_tx[tx_hash] = tx_height
                        txs.add(tx_hash)

        for tx_hash in txs:
            util.trigger_callback('adb_removed_verified_tx', self, tx_hash)
        for asset in assets:
            util.trigger_callback('adb_removed_verified_asset', self, asset)
        return txs

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        cached_local_height = getattr(self.threadlocal_cache, 'local_height', None)
        if cached_local_height is not None:
            return cached_local_height
        return self.network.get_local_height() if self.network else self.db.get('stored_height', 0)

    def set_future_tx(self, txid: str, *, wanted_height: int):
        """Mark a local tx as "future" (encumbered by a timelock).
        wanted_height is the min (abs) block height at which the tx can get into the mempool (be broadcast).
                      note: tx becomes consensus-valid to be mined in a block at height wanted_height+1
        In case of a CSV-locked tx with unconfirmed inputs, the wanted_height is a best-case guess.
        """
        with self.lock:
            old_height = self.future_tx.get(txid) or None
            self.future_tx[txid] = wanted_height
        if old_height != wanted_height:
            util.trigger_callback('adb_set_future_tx', self, txid)

    def get_tx_height(self, tx_hash: str) -> TxMinedInfo:
        if tx_hash is None:  # ugly backwards compat...
            return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                conf = max(self.get_local_height() - verified_tx_mined_info.height + 1, 0)
                return verified_tx_mined_info._replace(conf=conf)
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            elif tx_hash in self.unconfirmed_tx:
                height = self.unconfirmed_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            elif wanted_height := self.future_tx.get(tx_hash):
                if wanted_height > self.get_local_height():
                    return TxMinedInfo(height=TX_HEIGHT_FUTURE, conf=0, wanted_height=wanted_height)
                else:
                    return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
            else:
                # local transaction
                return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)

    def up_to_date_changed(self) -> None:
        # fire triggers
        util.trigger_callback('adb_set_up_to_date', self)

    def is_up_to_date(self):
        if not self.synchronizer or not self.verifier:
            return False
        #print(f'{self.synchronizer.is_up_to_date()=}')
        #print(f'{self.verifier.is_up_to_date()=}')
        return self.synchronizer.is_up_to_date() and self.verifier.is_up_to_date()

    def reset_netrequest_counters(self) -> None:
        if self.synchronizer:
            self.synchronizer.reset_request_counters()
        if self.verifier:
            self.verifier.reset_request_counters()

    def get_history_sync_state_details(self) -> Tuple[int, int]:
        nsent, nans = 0, 0
        if self.synchronizer:
            n1, n2 = self.synchronizer.num_requests_sent_and_answered()
            nsent += n1
            nans += n2
        if self.verifier:
            n1, n2 = self.verifier.num_requests_sent_and_answered()
            nsent += n1
            nans += n2
        return nsent, nans

    @with_transaction_lock
    def get_tx_delta(self, tx_hash: str, address: str) -> Mapping[Optional[str], int]:
        """effect of tx on address"""
        delta = defaultdict(int)
        # subtract the value of coins sent from address
        d = self.db.get_txi_addr(tx_hash, address)
        for n, v, asset in d:
            delta[asset] -= v
        # add the value of the coins received at address
        d = self.db.get_txo_addr(tx_hash, address)
        for n, (v, asset, cb) in d.items():
            delta[asset] += v
        return delta

    def get_tx_fee(self, txid: str) -> Optional[int]:
        """Returns tx_fee or None. Use server fee only if tx is unconfirmed and not mine.

        Note: being fast is prioritised over completeness here. We try to avoid deserializing
              the tx, as that is expensive if we are called for the whole history. We sometimes
              incorrectly early-exit and return None, e.g. for not-all-ismine-input txs,
              where we could calculate the fee if we deserialized (but to see if we have all
              the parent txs available, we would have to deserialize first).
        """
        # check if stored fee is available
        fee = self.db.get_tx_fee(txid, trust_server=False)
        if fee is not None:
            return fee
        # delete server-sent fee for confirmed txns
        confirmed = self.get_tx_height(txid).conf > 0
        if confirmed:
            self.db.add_tx_fee_from_server(txid, None)
        # if all inputs are ismine, try to calc fee now;
        # otherwise, return stored value
        num_all_inputs = self.db.get_num_all_inputs_of_tx(txid)
        if num_all_inputs is not None:
            # check if tx is mine
            num_ismine_inputs = self.db.get_num_ismine_inputs_of_tx(txid)
            assert num_ismine_inputs <= num_all_inputs, (num_ismine_inputs, num_all_inputs)
            # trust server if tx is unconfirmed and not mine
            if num_ismine_inputs < num_all_inputs:
                return None if confirmed else self.db.get_tx_fee(txid, trust_server=True)
        # lookup tx and deserialize it.
        # note that deserializing is expensive, hence above hacks
        tx = self.db.get_transaction(txid)
        if not tx:
            return None
        # compute fee if possible
        v_in = v_out = 0
        with self.lock, self.transaction_lock:
            for txin in tx.inputs():
                addr = self.get_txin_address(txin)
                value = self.get_txin_value(txin, address=addr)
                if value is None:
                    v_in = None
                elif v_in is not None:
                    v_in += value
            for txout in tx.outputs():
                v_out += txout.value
        if v_in is not None:
            fee = v_in - v_out
        else:
            fee = None
        # save result
        self.db.add_tx_fee_we_calculated(txid, fee)
        self.db.add_num_inputs_to_tx(txid, len(tx.inputs()))
        return fee

    def get_addr_io(self, address: str):
        with self.lock, self.transaction_lock:
            h = self.get_address_history(address).items()
            received = {}
            sent = {}
            for tx_hash, height in h:
                tx_mined_info = self.get_tx_height(tx_hash)
                txpos = tx_mined_info.txpos if tx_mined_info.txpos is not None else -1
                d = self.db.get_txo_addr(tx_hash, address)
                for n, (v, asset, is_cb) in d.items():
                    received[tx_hash + ':%d'%n] = (height, txpos, asset, v, is_cb)
                l = self.db.get_txi_addr(tx_hash, address)
                for txi, v, asset in l:
                    sent[txi] = tx_hash, height, txpos
        return received, sent

    def get_addr_outputs(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        received, sent = self.get_addr_io(address)
        out = {}
        for prevout_str, v in received.items():
            tx_height, tx_pos, asset, value, is_cb = v
            prevout = TxOutpoint.from_str(prevout_str)
            utxo = PartialTxInput(prevout=prevout, is_coinbase_output=is_cb)
            utxo._trusted_address = address
            utxo._trusted_value_sats = value
            utxo._trusted_asset = asset
            utxo.block_height = tx_height
            utxo.block_txpos = tx_pos
            if prevout_str in sent:
                txid, height, pos = sent[prevout_str]
                utxo.spent_txid = txid
                utxo.spent_height = height
            else:
                utxo.spent_txid = None
                utxo.spent_height = None
            out[prevout] = utxo
        return out

    def get_addr_utxo(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        out = self.get_addr_outputs(address)
        for k, v in list(out.items()):
            if v.spent_height is not None:
                out.pop(k)
        return out

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_assets_in_mempool(self, domain) -> Set[str]:
        cache_key = sha256(','.join(sorted(domain)) + ';')
        cached_value = self._get_assets_in_mempool_cache.get(cache_key)
        if cached_value:
            return cached_value
        self.get_balance(domain, asset_aware=True)
        return set(self._get_assets_in_mempool_cache.get(cache_key) or [])

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_balance(self, domain, *, excluded_addresses: Set[str] = None,
                    excluded_coins: Set[str] = None, asset_aware=False) -> Union[Tuple[int, int, int], Mapping[Optional[str], Tuple[int, int, int]]]:
        """Return the balance of a set of addresses:
        confirmed and matured, unconfirmed, unmatured
        """
        if excluded_addresses is None:
            excluded_addresses = set()
        assert isinstance(excluded_addresses, set), f"excluded_addresses should be set, not {type(excluded_addresses)}"
        domain = set(domain) - excluded_addresses
        if excluded_coins is None:
            excluded_coins = set()
        assert isinstance(excluded_coins, set), f"excluded_coins should be set, not {type(excluded_coins)}"

        cache_key = sha256(','.join(sorted(domain)) + ';'
                           + ','.join(sorted(excluded_coins)))
        
        if asset_aware:
            cached_value = self._get_asset_balance_cache.get(cache_key)
        else:
            cached_value = self._get_balance_cache.get(cache_key)
        
        if cached_value:
            return cached_value

        coins = {}  # type: Dict[TxOutpoint, PartialTxInput]
        for address in domain:
            coins.update(self.get_addr_outputs(address))

        if asset_aware:
            c = defaultdict(int)
            u = defaultdict(int)
            x = defaultdict(int)
            assets_in_mempool = set()
        else:
            c = u = x = 0
        
        mempool_height = self.get_local_height() + 1  # height of next block
        for utxo in coins.values():
            if utxo.spent_height is not None:
                continue
            if utxo.prevout.to_str() in excluded_coins:
                continue

            v = utxo.value_sats(asset_aware=asset_aware)
            tx_height = utxo.block_height
            is_cb = utxo.is_coinbase_output()
            if is_cb and tx_height + COINBASE_MATURITY > mempool_height:
                if asset_aware:
                    x[utxo.asset] += v
                else:
                    x += v
            elif tx_height > 0:
                if asset_aware:
                    c[utxo.asset] += v
                else:
                    c += v
            else:
                txid = utxo.prevout.txid.hex()
                tx = self.db.get_transaction(txid)
                assert tx is not None # txid comes from get_addr_io
                # we look at the outputs that are spent by this transaction
                # if those outputs are ours and confirmed, we count this coin as confirmed

                if asset_aware:
                    confirmed_spent_amount = defaultdict(int)
                else:
                    confirmed_spent_amount = 0
                
                for txin in tx.inputs():
                    if txin.prevout in coins:
                        coin = coins[txin.prevout]
                        if coin.block_height > 0:
                            if asset_aware:
                                confirmed_spent_amount[coin.asset] += coin.value_sats(asset_aware=asset_aware)
                            else:
                                confirmed_spent_amount += coin.value_sats(asset_aware=asset_aware)
                # Compare amount, in case tx has confirmed and unconfirmed inputs, or is a coinjoin.
                # (fixme: tx may have multiple change outputs)

                if asset_aware:
                    assets_in_mempool.add(utxo.asset)
                    if confirmed_spent_amount[utxo.asset] >= v:
                        c[utxo.asset] += v
                    else:
                        c[utxo.asset] += confirmed_spent_amount[utxo.asset]
                        u[utxo.asset] += v - confirmed_spent_amount[utxo.asset]
                else:
                    if confirmed_spent_amount >= v:
                        c += v
                    else:
                        c += confirmed_spent_amount
                        u += v - confirmed_spent_amount

        if asset_aware:
            result = defaultdict(lambda: (0, 0, 0))
            for asset in set(c.keys()).union(u.keys()).union(x.keys()):
                result[asset] = c[asset], u[asset], x[asset]
            self._get_asset_balance_cache[cache_key] = result
            self._get_assets_in_mempool_cache[cache_key] = assets_in_mempool
        else:
            result = c, u, x
            # cache result.
            # Cache needs to be invalidated if a transaction is added to/
            # removed from history; or on new blocks (maturity...)
            self._get_balance_cache[cache_key] = result
        return result

    @with_local_height_cached
    def get_utxos(
            self,
            domain,
            *,
            excluded_addresses=None,
            mature_only: bool = False,
            confirmed_funding_only: bool = False,
            confirmed_spending_only: bool = False,
            nonlocal_only: bool = False,
            block_height: int = None,
    ) -> Sequence[PartialTxInput]:
        if block_height is not None:
            # caller wants the UTXOs we had at a given height; check other parameters
            assert confirmed_funding_only
            assert confirmed_spending_only
            assert nonlocal_only
        else:
            block_height = self.get_local_height()
        coins = []
        domain = set(domain)
        if excluded_addresses:
            domain = set(domain) - set(excluded_addresses)
        mempool_height = block_height + 1  # height of next block
        for addr in domain:
            txos = self.get_addr_outputs(addr)
            for txo in txos.values():
                if txo.value_sats(asset_aware=True) == 0: continue
                if txo.spent_height is not None:
                    if not confirmed_spending_only:
                        continue
                    if confirmed_spending_only and 0 < txo.spent_height <= block_height:
                        continue
                if confirmed_funding_only and not (0 < txo.block_height <= block_height):
                    continue
                if nonlocal_only and txo.block_height in (TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE):
                    continue
                if (mature_only and txo.is_coinbase_output()
                        and txo.block_height + COINBASE_MATURITY > mempool_height):
                    continue
                coins.append(txo)
                continue
        return coins

    def is_used(self, address: str) -> bool:
        return self.get_address_history_len(address) != 0

    def is_empty(self, address: str) -> bool:
        coins = self.get_addr_utxo(address)
        return not bool(coins)

    @with_local_height_cached
    def address_is_old(self, address: str, *, req_conf: int = 3) -> bool:
        """Returns whether address has any history that is deeply confirmed.
        Used for reorg-safe(ish) gap limit roll-forward.
        """
        max_conf = -1
        h = self.db.get_addr_history(address)
        needs_spv_check = not self.config.NETWORK_SKIPMERKLECHECK
        for tx_hash, tx_height in h:
            if needs_spv_check:
                tx_age = self.get_tx_height(tx_hash).conf
            else:
                if tx_height <= 0:
                    tx_age = 0
                else:
                    tx_age = self.get_local_height() - tx_height + 1
            max_conf = max(max_conf, tx_age)
        return max_conf >= req_conf
