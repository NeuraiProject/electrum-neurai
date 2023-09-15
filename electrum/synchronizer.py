#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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
import hashlib
from typing import Dict, List, TYPE_CHECKING, Tuple, Set
from collections import defaultdict
import logging

from aiorpcx import run_in_thread, RPCError

from . import util, constants
from .transaction import Transaction, PartialTransaction
from .util import make_aiohttp_session, NetworkJobOnDefaultServer, random_shuffled_copy, OldTaskGroup
from .bitcoin import address_to_scripthash, is_address, is_b58_address, b58_address_to_hash160
from .asset import AssetMetadata, get_error_for_asset_name, get_error_for_asset_typed, AssetType
from .logging import Logger
from .interface import GracefulDisconnect, NetworkTimeout
from .i18n import _

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer


class SynchronizerFailure(Exception): pass


def history_status(h):
    if not h:
        return None
    status = ''
    for tx_hash, height in h:
        status += tx_hash + ':%d:' % height
    return hashlib.sha256(status.encode('ascii')).digest().hex()


def asset_status(asset_data):
    if not asset_data:
        return None
    if isinstance(asset_data, AssetMetadata):
        return asset_data.status()

    sat_amount = asset_data['sats_in_circulation']
    div_amt = asset_data['divisions']
    reissuable = False if asset_data['reissuable'] == 0 else True
    has_ipfs = False if asset_data['has_ipfs'] == 0 else True

    h = ''.join([str(sat_amount), str(div_amt), str(reissuable), str(has_ipfs)])
    if has_ipfs:
        h += asset_data['ipfs']

    return hashlib.sha256(h.encode('ascii')).digest().hex()

def qualifier_tag_status(d):
    if not d:
        return None
    status = ';'.join(f'{h160}:{d1["height"]}{d1["tx_hash"]}{d1["tx_pos"]}{d1["flag"]}' for h160, d1 in sorted(d.items(), key=lambda x: x[0]))
    return hashlib.sha256(status.encode('ascii')).digest().hex()

def h160_tag_status(d):
    if not d:
        return None
    status = ';'.join(f'{asset}:{d["height"]}{d["tx_hash"]}{d["tx_pos"]}{d["flag"]}' for asset, d in sorted(d.items(), key=lambda x: x[0]))
    return hashlib.sha256(status.encode('ascii')).digest().hex()

def broadcast_status(broadcasts):
    if not broadcasts:
        return None
    status = ';'.join(f'{d["tx_hash"]}:{d["height"]}{d["tx_pos"]}{d["data"]}{d["expiration"]}' for d in sorted(broadcasts, key=lambda x: (x["height"], x['tx_hash'], x["tx_pos"])))
    return hashlib.sha256(status.encode('ascii')).digest().hex()

class SynchronizerBase(NetworkJobOnDefaultServer):
    """Subscribe over the network to a set of addresses, and monitor their statuses.
    Every time a status changes, run a coroutine provided by the subclass.
    """
    def __init__(self, network: 'Network'):
        self.asyncio_loop = network.asyncio_loop

        NetworkJobOnDefaultServer.__init__(self, network)

    def _reset(self):
        super()._reset()
        self._adding_addrs = set()
        self.requested_addrs = set()
        self._handling_addr_statuses = set()
        self.scripthash_to_address = {}
        self._processed_some_notifications = False  # so that we don't miss them
        
        self._adding_assets = set()
        self.requested_assets = set()
        self._handling_asset_statuses = set()
        self._processed_some_asset_notifications = False

        self._adding_qualifiers_for_tags = set()
        self.requested_qualifiers_for_tags = set()
        self._handling_qualifiers_for_tags_statuses = set()
        self._processed_some_qualifier_for_tags_notifications = False

        self._adding_h160s_for_tags = set()
        self.requested_h160s_for_tags = set()
        self._handling_h160s_for_tags_statuses = set()
        self._processed_some_h160_for_tags_notifications = False

        self._adding_restricted_for_verifier = set()
        self.requested_restricted_for_verifier = set()
        self._handling_restricted_for_verifier = set()
        self._processed_some_restricted_for_verifier = False

        self._adding_restricted_for_freeze = set()
        self.requested_restricted_for_freeze = set()
        self._handling_restricted_for_freeze = set()
        self._processed_some_restricted_for_freeze = False

        self._adding_broadcasts = set()
        self.requested_broadcasts = set()
        self._handling_broadcast_statuses = set()
        self._processed_some_broadcasts = False

        # Queues
        self.asset_status_queue = asyncio.Queue()
        self.status_queue = asyncio.Queue()
        self.qualifier_tags_status_queue = asyncio.Queue()
        self.h160_tags_status_queue = asyncio.Queue()
        self.restricted_verifier_queue = asyncio.Queue()
        self.restricted_freeze_queue = asyncio.Queue()
        self.broadcast_status_queue = asyncio.Queue()

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        try:
            async with taskgroup as group:
                await group.spawn(self.handle_status())
                await group.spawn(self.handle_asset_status())
                await group.spawn(self.handle_qualifier_for_tags_status())
                await group.spawn(self.handle_h160_for_tags_status())
                await group.spawn(self.handle_restricted_for_verifier_update())
                await group.spawn(self.handle_restricted_for_freeze_update())
                await group.spawn(self.handle_broadcast_status())
                await group.spawn(self.main())
        finally:
            # we are being cancelled now
            self.session.unsubscribe(self.status_queue)
            self.session.unsubscribe(self.asset_status_queue)
            self.session.unsubscribe(self.qualifier_tags_status_queue)
            self.session.unsubscribe(self.h160_tags_status_queue)
            self.session.unsubscribe(self.restricted_verifier_queue)
            self.session.unsubscribe(self.restricted_freeze_queue)
            self.session.unsubscribe(self.broadcast_status_queue)

    def add(self, addr):
        if not is_address(addr): raise ValueError(f"invalid bitcoin address {addr}")
        self._adding_addrs.add(addr)  # this lets is_up_to_date already know about addr

    def add_asset(self, asset):
        if error := get_error_for_asset_name(asset): raise ValueError(f'invalid asset: {error}')
        self._adding_assets.add(asset)

    def add_qualifier_for_tag(self, asset):
        if get_error_for_asset_typed(asset, AssetType.QUALIFIER) and \
            get_error_for_asset_typed(asset, AssetType.SUB_QUALIFIER) and \
            get_error_for_asset_typed(asset, AssetType.RESTRICTED): raise ValueError(f'invalid asset')
        self._adding_qualifiers_for_tags.add(asset)

    def add_h160_for_tag(self, h160: str):
        if len(h160) != 40: raise ValueError(f'{h160} is not a valid h160 hex string')
        self._adding_h160s_for_tags.add(h160)

    def add_restricted_for_verifier(self, asset: str):
        if error := get_error_for_asset_typed(asset, AssetType.RESTRICTED): raise ValueError(f'invalid asset: {error}')
        self._adding_restricted_for_verifier.add(asset)

    def add_restricted_for_freeze(self, asset: str):
        if error := get_error_for_asset_typed(asset, AssetType.RESTRICTED): raise ValueError(f'invalid asset: {error}')
        self._adding_restricted_for_freeze.add(asset)

    def add_broadcast(self, asset: str):
        if error := get_error_for_asset_name(asset): raise ValueError(f'invalid asset: {error}')
        self._adding_broadcasts.add(asset)

    async def _add_address(self, addr: str):
        try:
            if not is_address(addr): raise ValueError(f"invalid bitcoin address {addr}")
            if addr in self.requested_addrs: return
            self.requested_addrs.add(addr)
            await self.taskgroup.spawn(self._subscribe_to_address, addr)
        finally:
            self._adding_addrs.discard(addr)  # ok for addr not to be present

    async def _add_asset(self, asset: str):
        try:
            if error := get_error_for_asset_name(asset): raise ValueError(f'invalid asset: {error}')
            if asset in self.requested_assets: return
            self.requested_assets.add(asset)
            await self.taskgroup.spawn(self._subscribe_to_asset, asset)
        finally:
            self._adding_assets.discard(asset)

    async def _add_qualifier_for_tags(self, asset: str):
        try:
            if asset in self.requested_qualifiers_for_tags: return
            self.requested_qualifiers_for_tags.add(asset)
            await self.taskgroup.spawn(self._subscribe_to_qualifier_for_tags, asset)
        finally:
            self._adding_qualifiers_for_tags.discard(asset)

    async def _add_h160_for_tags(self, h160: str):
        try:
            if h160 in self.requested_h160s_for_tags: return
            self.requested_h160s_for_tags.add(h160)
            await self.taskgroup.spawn(self._subscribe_to_h160_for_tags, h160)
        finally:
            self._adding_h160s_for_tags.discard(h160)

    async def _add_restricted_for_verifier(self, asset: str):
        try:
            if asset in self.requested_restricted_for_verifier: return
            self.requested_restricted_for_verifier.add(asset)
            await self.taskgroup.spawn(self._subscribe_to_restricted_for_verifier, asset)
        finally:
            self._adding_restricted_for_verifier.discard(asset)

    async def _add_restricted_for_freeze(self, asset: str):
        try:
            if asset in self.requested_restricted_for_freeze: return
            self.requested_restricted_for_freeze.add(asset)
            await self.taskgroup.spawn(self._subscribe_to_restricted_for_freeze, asset)
        finally:
            self._adding_restricted_for_freeze.discard(asset)

    async def _add_broadcast(self, asset: str):
        try:
            if asset in self.requested_broadcasts: return
            self.requested_broadcasts.add(asset)
            await self.taskgroup.spawn(self._subscribe_to_broadcast, asset)
        finally:
            self._adding_broadcasts.discard(asset)

    async def _on_address_status(self, addr, status):
        """Handle the change of the status of an address.
        Should remove addr from self._handling_addr_statuses when done.
        """
        raise NotImplementedError()  # implemented by subclasses

    async def _on_asset_status(self, asset, status):
        raise NotImplementedError()

    async def _on_qualifier_for_tags_status(self, asset, status):
        raise NotImplementedError()

    async def _on_h160_for_tags_status(self, h160, status):
        raise NotImplementedError()
    
    async def _on_restricted_for_verifier_update(self, asset, data):
        raise NotImplementedError()
    
    async def _on_restricted_for_freeze_update(self, asset, data):
        raise NotImplementedError()

    async def _on_broadcast_status(self, asset, status):
        raise NotImplementedError()

    async def _subscribe_to_address(self, addr):
        h = address_to_scripthash(addr)
        self.scripthash_to_address[h] = addr
        self._requests_sent += 1
        try:
            async with self._network_request_semaphore:
                await self.session.subscribe('blockchain.scripthash.subscribe', [h], self.status_queue)
        except RPCError as e:
            if e.message == 'history too large':  # no unique error code
                raise GracefulDisconnect(e, log_level=logging.ERROR) from e
            raise
        self._requests_answered += 1

    async def _subscribe_to_asset(self, asset):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.asset.subscribe', [asset], self.asset_status_queue)
        self._requests_answered += 1

    async def _subscribe_to_qualifier_for_tags(self, asset):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.tag.qualifier.subscribe', [asset], self.qualifier_tags_status_queue)
        self._requests_answered += 1

    async def _subscribe_to_h160_for_tags(self, h160):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.tag.h160.subscribe', [h160], self.h160_tags_status_queue)
        self._requests_answered += 1

    async def _subscribe_to_restricted_for_verifier(self, asset):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.asset.verifier_string.subscribe', [asset], self.restricted_verifier_queue)
        self._requests_answered += 1

    async def _subscribe_to_restricted_for_freeze(self, asset):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.asset.is_frozen.subscribe', [asset], self.restricted_freeze_queue)
        self._requests_answered += 1

    async def _subscribe_to_broadcast(self, asset):
        self._requests_sent += 1
        async with self._network_request_semaphore:
            await self.session.subscribe('blockchain.asset.broadcasts.subscribe', [asset], self.broadcast_status_queue)
        self._requests_answered += 1

    async def handle_status(self):
        while True:
            h, status = await self.status_queue.get()
            addr = self.scripthash_to_address[h]
            self._handling_addr_statuses.add(addr)
            self.requested_addrs.discard(addr)  # ok for addr not to be present
            await self.taskgroup.spawn(self._on_address_status, addr, status)
            self._processed_some_notifications = True

    async def handle_asset_status(self):
        while True:
            asset, status = await self.asset_status_queue.get()
            self._handling_asset_statuses.add(asset)
            self.requested_assets.discard(asset)
            await self.taskgroup.spawn(self._on_asset_status, asset, status)
            self._processed_some_asset_notifications = True

    async def handle_qualifier_for_tags_status(self):
        while True:
            asset, status = await self.qualifier_tags_status_queue.get()
            self._handling_qualifiers_for_tags_statuses.add(asset)
            self.requested_qualifiers_for_tags.discard(asset)
            await self.taskgroup.spawn(self._on_qualifier_for_tags_status, asset, status)
            self._processed_some_qualifier_for_tags_notifications = True

    async def handle_h160_for_tags_status(self):
        while True:
            h160, status = await self.h160_tags_status_queue.get()
            self._handling_h160s_for_tags_statuses.add(h160)
            self.requested_h160s_for_tags.discard(h160)
            await self.taskgroup.spawn(self._on_h160_for_tags_status, h160, status)
            self._processed_some_h160_for_tags_notifications = True

    async def handle_restricted_for_verifier_update(self):
        while True:
            asset, data = await self.restricted_verifier_queue.get()
            self._handling_restricted_for_verifier.add(asset)
            self.requested_restricted_for_verifier.discard(asset)
            await self.taskgroup.spawn(self._on_restricted_for_verifier_update, asset, data)
            self._processed_some_restricted_for_verifier = True

    async def handle_restricted_for_freeze_update(self):
        while True:
            asset, data = await self.restricted_freeze_queue.get()
            self._handling_restricted_for_freeze.add(asset)
            self.requested_restricted_for_freeze.discard(asset)
            await self.taskgroup.spawn(self._on_restricted_for_freeze_update, asset, data)
            self._processed_some_restricted_for_freeze = True

    async def handle_broadcast_status(self):
        while True:
            asset, status = await self.broadcast_status_queue.get()
            self._handling_broadcast_statuses.add(asset)
            self.requested_broadcasts.discard(asset)
            await self.taskgroup.spawn(self._on_broadcast_status, asset, status)
            self._processed_some_broadcasts = True

    async def main(self):
        raise NotImplementedError()  # implemented by subclasses


class Synchronizer(SynchronizerBase):
    '''The synchronizer keeps the wallet up-to-date with its set of
    addresses and their transactions.  It subscribes over the network
    to wallet addresses, gets the wallet to generate new addresses
    when necessary, requests the transaction history of any addresses
    we don't have the full history of, and requests binary transaction
    data of any transactions the wallet doesn't have.
    '''
    def __init__(self, adb: 'AddressSynchronizer'):
        self.adb = adb
        SynchronizerBase.__init__(self, adb.network)

    def _reset(self):
        super()._reset()
        self._init_done = False
        self.requested_tx = {}

        self.requested_histories = set()
        self.requested_asset_metadata = set()
        self.requested_qualifiers_for_tags_results = set()
        self.requested_h160s_for_tags_results = set()
        self.requested_restricted_for_verifier_results = set()
        self.requested_restricted_for_freeze_results = set()
        self.requested_broadcast_history = set()

        self._stale_histories = dict()  # type: Dict[str, asyncio.Task]
        self._stale_asset_metadatas = dict()  # type: Dict[str, asyncio.Task]
        self._stale_qualifiers_for_tags = dict()  # type: Dict[str, asyncio.Task]
        self._stale_h160s_for_tags = dict()
        self._stale_restricted_for_verifier = dict()
        self._stale_restricted_for_freeze = dict()
        self._stale_broadcast_history = dict()

    def diagnostic_name(self):
        return self.adb.diagnostic_name()

    def is_up_to_date(self):
        return (self._init_done
                and not self._adding_addrs
                and not self.requested_addrs
                and not self._handling_addr_statuses
                and not self.requested_histories
                and not self.requested_tx
                and not self._stale_histories

                and not self._adding_assets
                and not self.requested_assets
                and not self._handling_asset_statuses
                and not self.requested_asset_metadata
                and not self._stale_asset_metadatas

                and not self._adding_qualifiers_for_tags
                and not self.requested_qualifiers_for_tags
                and not self._handling_qualifiers_for_tags_statuses
                and not self.requested_qualifiers_for_tags_results
                and not self._stale_qualifiers_for_tags

                and not self._adding_h160s_for_tags
                and not self.requested_h160s_for_tags
                and not self._handling_h160s_for_tags_statuses
                and not self.requested_h160s_for_tags_results
                and not self._stale_h160s_for_tags

                and not self._adding_restricted_for_verifier
                and not self.requested_restricted_for_verifier
                and not self._handling_restricted_for_verifier
                and not self.requested_restricted_for_verifier_results
                and not self._stale_restricted_for_verifier

                and not self._adding_restricted_for_freeze
                and not self.requested_restricted_for_freeze
                and not self._handling_restricted_for_freeze
                and not self.requested_restricted_for_freeze_results
                and not self._stale_restricted_for_freeze

                and not self._adding_broadcasts
                and not self.requested_broadcasts
                and not self._handling_broadcast_statuses
                and not self.requested_broadcast_history
                and not self._stale_broadcast_history

                and self.status_queue.empty()
                and self.asset_status_queue.empty()
                and self.qualifier_tags_status_queue.empty()
                and self.h160_tags_status_queue.empty()
                and self.restricted_verifier_queue.empty()
                and self.restricted_freeze_queue.empty()
                and self.broadcast_status_queue.empty())

    async def _on_restricted_for_freeze_update(self, asset, data):
        data_id = f'{data["frozen"]}:{data["tx_hash"]}:{data["height"]}' if data else ''
        try:
            freeze_dict = self.adb.get_restricted_freeze_for_synchronizer(asset)
            if freeze_dict == data:
                return
            if not data:
                if freeze_dict:
                    raise SynchronizerFailure(f'Server is not sending freeze for verified restricted asset {asset}')
                return
            if (asset, data_id) in self.requested_restricted_for_freeze_results:
                return
            self.requested_restricted_for_freeze_results.add((asset, data_id))
        finally:
            self._handling_restricted_for_freeze.discard(asset)
        self.logger.info(f'receiving freeze for asset {asset}: {data["frozen"]}')
        verified_data = self.adb.db.get_verified_restricted_freeze(asset)
        if verified_data and verified_data['height'] > data['height'] > 0:
            raise SynchronizerFailure(f'Server is trying to send old freeze for {asset}')            
        self.adb.add_unverified_or_unconfirmed_freeze_for_restricted(asset, data)
        self.requested_restricted_for_freeze_results.discard((asset, data_id))

    async def _on_restricted_for_verifier_update(self, asset, data):
        data_id = f'{data["string"]}:{data["tx_hash"]}:{data["height"]}' if data else ''
        try:
            verifier_dict = self.adb.get_restricted_verifier_string_for_synchronizer(asset)
            if verifier_dict == data:
                return
            if not data:
                if verifier_dict:
                    raise SynchronizerFailure(f'Server is not sending verifier string for verified restricted asset {asset}')
                return
            if (asset, data_id) in self.requested_restricted_for_verifier_results:
                return
            self.requested_restricted_for_verifier_results.add((asset, data_id))
        finally:
            self._handling_restricted_for_verifier.discard(asset)
        self.logger.info(f'receiving verifier for asset {asset}: {data["string"]}')
        verified_data = self.adb.db.get_verified_restricted_verifier(asset)
        if verified_data and verified_data['height'] > data['height'] > 0:
            raise SynchronizerFailure(f'Server is trying to send old tag verifier string for {asset}')            
        self.adb.add_unverified_or_unconfirmed_verifier_string_for_restricted(asset, data)
        self.requested_restricted_for_verifier_results.discard((asset, data_id))

    async def _on_broadcast_status(self, asset, status):
        try:
            broadcasts = self.adb.get_broadcasts_for_synchronizer(asset)
            if broadcast_status(broadcasts) == status:
                return
            if (asset, status) in self.requested_broadcast_history:
                return
            self.requested_broadcast_history.add((asset, status))
            self._stale_broadcast_history.pop(asset, asyncio.Future()).cancel()
        finally:
            self._handling_broadcast_statuses.discard(asset)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_broadcasts_for_asset(asset)
        self._requests_answered += 1
        self.logger.info(f'receiving broadcasts for {asset}: {status}')
        if broadcast_status(result) != status:
            self.logger.info(f'error: broadcast status mismatch {asset}. we\'ll wait a bit for status update.')
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f'timeout reached waiting for broadcast {asset}: still stale')
            self._stale_broadcast_history[asset] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_broadcast_history.pop(asset, asyncio.Future()).cancel()
            self.adb.add_unverified_or_unconfirmed_broadcasts(asset, {d['tx_hash']: {k: v for k, v in d.items() if k != 'tx_hash'} for d in result})
        self.requested_broadcast_history.discard((asset, status))

    async def _on_h160_for_tags_status(self, h160, status):
        try:
            tags = self.adb.get_h160_tags_for_synchronizer(h160)
            if h160_tag_status(tags) == status:
                return
            if (h160, status) in self.requested_h160s_for_tags_results:
                return
            self.requested_h160s_for_tags_results.add((h160, status))
            self._stale_h160s_for_tags.pop(h160, asyncio.Future()).cancel()
        finally:
            self._handling_h160s_for_tags_statuses.discard(h160)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_tags_for_h160(h160)
        self._requests_answered += 1
        self.logger.info(f'receiving tags for h160 {h160}: {result.keys()}')
        if h160_tag_status(result) != status:
            self.logger.info(f"error: h160 tag status mismatch: {h160}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for h160 {h160}: tags still stale")
            self._stale_h160s_for_tags[h160] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_h160s_for_tags.pop(h160, asyncio.Future()).cancel()
            verified_tags = self.adb.db.get_verified_h160_tags(h160)
            if verified_tags:
                if any(asset not in result.keys() for asset in verified_tags.keys()):
                    raise SynchronizerFailure(f'verified assets are missing from tags for {h160}')
                for asset, asset_d in verified_tags.items():
                    if 0 < result[asset]['height'] < asset_d['height']:
                        self.requested_h160s_for_tags_results.discard((h160, status))
                        raise SynchronizerFailure(f'Server is trying to send old tag data for {h160} {asset}')            
            self.adb.add_unverified_or_unconfirmed_tags_for_h160(h160, result)
        self.requested_h160s_for_tags_results.discard((h160, status))

    async def _on_qualifier_for_tags_status(self, asset, status):
        try:
            tags = self.adb.get_qualifier_tags_for_synchronizer(asset)
            if qualifier_tag_status(tags) == status:
                return
            if (asset, status) in self.requested_qualifiers_for_tags_results:
                return
            self.requested_qualifiers_for_tags_results.add((asset, status))
            self._stale_qualifiers_for_tags.pop(asset, asyncio.Future()).cancel()
        finally:
            self._handling_qualifiers_for_tags_statuses.discard(asset)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_tags_for_qualifier(asset)
        self._requests_answered += 1
        self.logger.info(f'receiving tags for qualifier {asset}: {result.keys()}')
        if qualifier_tag_status(result) != status:
            self.logger.info(f"error: qualifier tag status mismatch: {asset}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for qualifier {asset}: tags still stale")
            self._stale_qualifiers_for_tags[asset] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_qualifiers_for_tags.pop(asset, asyncio.Future()).cancel()
            verified_tags = self.adb.db.get_verified_qualifier_tags(asset)
            if verified_tags:
                if any(h160 not in result.keys() for h160 in verified_tags.keys()):
                    raise SynchronizerFailure(f'verified h160s are missing from tags for {asset}')
                for h160, h160_d in verified_tags.items():
                    if 0 < result[h160]['height'] < h160_d['height']:
                        self.requested_qualifiers_for_tags_results.discard((asset, status))
                        raise SynchronizerFailure(f'Server is trying to send old tag data for {asset} {h160}')            
            self.adb.add_unverified_or_unconfirmed_tags_for_qualifier(asset, result)
        self.requested_qualifiers_for_tags_results.discard((asset, status))

    async def _on_asset_status(self, asset, status):
        try:
            metadata = self.adb.get_metadata_for_synchronizer(asset)
            if asset_status(metadata) == status:
                return
            if (asset, status) in self.requested_asset_metadata:
                return
            self.requested_asset_metadata.add((asset, status))
            self._stale_asset_metadatas.pop(asset, asyncio.Future()).cancel()
        finally:
            self._handling_asset_statuses.discard(asset)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_asset_metadata(asset)
        self._requests_answered += 1
        self.logger.info(f'receiving metadata {asset}: {result}')
        if asset_status(result) != status:
            self.logger.info(f"error: asset status mismatch: {asset}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for asset {asset}: metadata still stale")
            self._stale_asset_metadatas[asset] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_asset_metadatas.pop(asset, asyncio.Future()).cancel()
            base_tup = self.adb.db.get_verified_asset_metadata_base_source(asset)
            if base_tup is not None and 0 < result['source']['height'] < base_tup[1]:
                self.requested_asset_metadata.discard((asset, status))
                raise SynchronizerFailure(_('Server is trying to send old metadata for {}').format(asset), log_level=logging.ERROR)            
            self.adb.add_unverified_or_unconfirmed_asset_metadata(asset, result)
        self.requested_asset_metadata.discard((asset, status))

    async def _on_address_status(self, addr, status):
        try:
            history = self.adb.db.get_addr_history(addr)
            if history_status(history) == status:
                return
            # No point in requesting history twice for the same announced status.
            # However if we got announced a new status, we should request history again:
            if (addr, status) in self.requested_histories:
                return
            # request address history
            self.requested_histories.add((addr, status))
            self._stale_histories.pop(addr, asyncio.Future()).cancel()
        finally:
            self._handling_addr_statuses.discard(addr)
        h = address_to_scripthash(addr)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_history_for_scripthash(h)
        self._requests_answered += 1
        self.logger.info(f"receiving history {addr} {len(result)}")
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Check that the status corresponds to what was announced
        if history_status(hist) != status:
            # could happen naturally if history changed between getting status and history (race)
            self.logger.info(f"error: status mismatch: {addr}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for addr {addr}: history still stale")
            self._stale_histories[addr] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_histories.pop(addr, asyncio.Future()).cancel()
            # Store received history
            self.adb.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            await self._request_missing_txs(hist)

        # Remove request; this allows up_to_date to be True
        self.requested_histories.discard((addr, status))

    async def _request_missing_txs(self, hist, *, allow_server_not_finding_tx=False):
        # "hist" is a list of [tx_hash, tx_height] lists
        transaction_hashes = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            tx = self.adb.db.get_transaction(tx_hash)
            if tx and not isinstance(tx, PartialTransaction):
                continue  # already have complete tx
            transaction_hashes.append(tx_hash)
            self.requested_tx[tx_hash] = tx_height

        if not transaction_hashes: return
        async with OldTaskGroup() as group:
            for tx_hash in transaction_hashes:
                await group.spawn(self._get_transaction(tx_hash, allow_server_not_finding_tx=allow_server_not_finding_tx))

    async def _get_transaction(self, tx_hash, *, allow_server_not_finding_tx=False):
        self._requests_sent += 1
        try:
            async with self._network_request_semaphore:
                raw_tx = await self.interface.get_transaction(tx_hash)
        except RPCError as e:
            # most likely, "No such mempool or blockchain transaction"
            if allow_server_not_finding_tx:
                self.requested_tx.pop(tx_hash)
                return
            else:
                raise
        finally:
            self._requests_answered += 1
        tx = Transaction(raw_tx)
        if tx_hash != tx.txid():
            raise SynchronizerFailure(f"received tx does not match expected txid ({tx_hash} != {tx.txid()})")
        tx_height = self.requested_tx.pop(tx_hash)
        self.adb.receive_tx_callback(tx_hash, tx, tx_height)
        self.logger.info(f"received tx {tx_hash} height: {tx_height} bytes: {len(raw_tx)}")

    async def main(self):
        self.adb.up_to_date_changed()
        # request missing txns, if any
        for addr in random_shuffled_copy(self.adb.db.get_history()):
            history = self.adb.db.get_addr_history(addr)
            # Old electrum servers returned ['*'] when all history for the address
            # was pruned. This no longer happens but may remain in old wallets.
            if history == ['*']: continue
            await self._request_missing_txs(history, allow_server_not_finding_tx=True)
        # add addresses to bootstrap
        for addr in random_shuffled_copy(self.adb.get_addresses()):
            await self._add_address(addr)
            if is_b58_address(addr):
                addr_type, h160 = b58_address_to_hash160(addr)
                if addr_type == constants.net.ADDRTYPE_P2PKH:
                    h160_h = h160.hex()
                    if h160_h not in self.adb.db.verified_tags_for_h160s:
                        self.adb.db.verified_tags_for_h160s[h160_h] = dict()
                    await self._add_h160_for_tags(h160_h)
        for asset in random_shuffled_copy(self.adb.get_assets_to_watch()):
            await self._add_asset(asset)
            if asset[-1] == '!':
                # Watch normal asset
                await self._add_asset(asset[:-1])
                if get_error_for_asset_typed(asset[:-1], AssetType.ROOT) is None:
                    # Watch for restricted of this asset
                    restricted_asset = f'${asset[:-1]}'
                    await self._add_asset(restricted_asset)
                    await self._add_qualifier_for_tags(restricted_asset)
                    await self._add_restricted_for_verifier(restricted_asset)
                    await self._add_restricted_for_freeze(restricted_asset)
            if asset[0] == '#':
                await self._add_qualifier_for_tags(asset)
            if asset[0] == '$':
                await self._add_qualifier_for_tags(asset)
                await self._add_restricted_for_verifier(asset)
                await self._add_restricted_for_freeze(asset)

        for asset in random_shuffled_copy(self.adb.get_broadcasts_to_watch()):
            await self._add_broadcast(asset)

        # main loop
        self._init_done = True
        prev_uptodate = False
        while True:
            await asyncio.sleep(0.1)
            for addr in self._adding_addrs.copy(): # copy set to ensure iterator stability
                await self._add_address(addr)
            for asset in self._adding_assets.copy():
                await self._add_asset(asset)
            for asset in self._adding_qualifiers_for_tags.copy():
                await self._add_qualifier_for_tags(asset)
            for h160 in self._adding_h160s_for_tags.copy():
                await self._add_h160_for_tags(h160)
            for asset in self._adding_restricted_for_verifier.copy():
                await self._add_restricted_for_verifier(asset)
            for asset in self._adding_restricted_for_freeze.copy():
                await self._add_restricted_for_freeze(asset)
            for asset in self._adding_broadcasts.copy():
                await self._add_broadcast(asset)
            up_to_date = self.adb.is_up_to_date()
            # see if status changed
            if (up_to_date != prev_uptodate
                    or up_to_date and (self._processed_some_notifications or self._processed_some_asset_notifications or
                                       self._processed_some_qualifier_for_tags_notifications or self._processed_some_h160_for_tags_notifications or
                                       self._processed_some_restricted_for_verifier or self._processed_some_restricted_for_freeze or
                                       self._processed_some_broadcasts)):
                self._processed_some_notifications = False
                self._processed_some_asset_notifications = False
                self._processed_some_qualifier_for_tags_notifications = False
                self._processed_some_h160_for_tags_notifications = False
                self._processed_some_restricted_for_verifier = False
                self._processed_some_restricted_for_freeze = False
                self._processed_some_broadcasts = False
                self.adb.up_to_date_changed()
            prev_uptodate = up_to_date


class Notifier(SynchronizerBase):
    """Watch addresses. Every time the status of an address changes,
    an HTTP POST is sent to the corresponding URL.
    """
    def __init__(self, network):
        SynchronizerBase.__init__(self, network)
        self.watched_addresses = defaultdict(list)  # type: Dict[str, List[str]]
        self._start_watching_queue = asyncio.Queue()  # type: asyncio.Queue[Tuple[str, str]]

    async def main(self):
        # resend existing subscriptions if we were restarted
        for addr in self.watched_addresses:
            await self._add_address(addr)
        # main loop
        while True:
            addr, url = await self._start_watching_queue.get()
            self.watched_addresses[addr].append(url)
            await self._add_address(addr)

    async def start_watching_addr(self, addr: str, url: str):
        await self._start_watching_queue.put((addr, url))

    async def stop_watching_addr(self, addr: str):
        self.watched_addresses.pop(addr, None)
        # TODO blockchain.scripthash.unsubscribe

    async def _on_address_status(self, addr, status):
        if addr not in self.watched_addresses:
            return
        self.logger.info(f'new status for addr {addr}')
        headers = {'content-type': 'application/json'}
        data = {'address': addr, 'status': status}
        for url in self.watched_addresses[addr]:
            try:
                async with make_aiohttp_session(proxy=self.network.proxy, headers=headers) as session:
                    async with session.post(url, json=data, headers=headers) as resp:
                        await resp.text()
            except Exception as e:
                self.logger.info(repr(e))
            else:
                self.logger.info(f'Got Response for {addr}')
