# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2012 Thomas Voegtlin
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
from typing import Sequence, Optional, TYPE_CHECKING, Tuple

import aiorpcx

from .util import TxMinedInfo, NetworkJobOnDefaultServer
from .crypto import sha256d
from .asset import (get_asset_info_from_script, AssetMetadata, AssetException, MetadataAssetVoutInformation, OwnerAssetVoutInformation,
                    AssetVoutType)
from .bitcoin import hash_decode, hash_encode, base_decode
from .transaction import Transaction, TxOutpoint
from .blockchain import hash_header
from .interface import GracefulDisconnect, RequestCorrupted
from . import constants

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer


class MerkleVerificationFailure(Exception): pass
class MissingBlockHeader(MerkleVerificationFailure): pass
class MerkleRootMismatch(MerkleVerificationFailure): pass
class InnerNodeOfSpvProofIsValidTx(MerkleVerificationFailure): pass


class SPV(NetworkJobOnDefaultServer):
    """ Simple Payment Verification """

    def __init__(self, network: 'Network', wallet: 'AddressSynchronizer'):
        self.wallet = wallet
        NetworkJobOnDefaultServer.__init__(self, network)

    def _reset(self):
        super()._reset()
        self.merkle_roots = {}  # txid -> merkle root (once it has been verified)
        self.requested_merkle = set()  # txid set of pending requests
        self.verifying = set()

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        async with taskgroup as group:
            await group.spawn(self.main)

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    async def main(self):
        self.blockchain = self.network.blockchain()
        while True:
            await self._maybe_undo_verifications()
            await self._request_proofs()
            await asyncio.sleep(0.1)

    async def _maybe_defer(self, tx_hash: str, tx_height: int, *, for_tx=False, add_to_requested_set=True, alt_id=None) -> bool:
        local_height = self.blockchain.height()
        if alt_id and alt_id in self.verifying:
            return True
        # do not request merkle branch if we already requested it
        if tx_hash in self.requested_merkle:
            return True
        if tx_hash in self.merkle_roots:
            if for_tx and self.wallet.db.get_verified_tx(tx_hash): 
                return True
        # or before headers are available
        if not (0 < tx_height <= local_height):
            return True
        # if it's in the checkpoint region, we still might not have the header
        header = self.blockchain.read_header(tx_height)
        if header is None:
            if tx_height < constants.net.max_checkpoint():
                # FIXME these requests are not counted (self._requests_sent += 1)
                await self.taskgroup.spawn(self.interface.request_chunk(tx_height, None, can_return_early=True))
            return True
        # request now
        if add_to_requested_set:
            self.requested_merkle.add(tx_hash)
        return False

    async def _request_proofs(self):
        unverified = self.wallet.get_unverified_txs()
        for tx_hash, tx_height in unverified.items():
            if await self._maybe_defer(tx_hash, tx_height, for_tx=True): continue
            await self.taskgroup.spawn(self._verify_unverified_transaction, tx_hash, tx_height)

        unverified_assets = self.wallet.get_unverified_asset_metadatas()
        for asset, (metadata, source_tuple, divisions_tuple, associated_data_tuple) in unverified_assets.items():
            source_txid = source_tuple[0].txid.hex()
            source_height = source_tuple[1]
            verifying_id = f'm:{asset}'
            if await self._maybe_defer(source_txid, source_height, add_to_requested_set=False, alt_id=verifying_id): continue
            if divisions_tuple:
                source_txid = divisions_tuple[0].txid.hex()
                source_height = divisions_tuple[1]
                if await self._maybe_defer(source_txid, source_height, add_to_requested_set=False, alt_id=verifying_id): continue
            if associated_data_tuple:
                source_txid = associated_data_tuple[0].txid.hex()
                source_height = associated_data_tuple[1]
                if await self._maybe_defer(source_txid, source_height, add_to_requested_set=False, alt_id=verifying_id): continue
            self.logger.info(f'attempting to verify {asset}')
            await self.taskgroup.spawn(self._verify_unverified_asset_metadata(asset, metadata, source_tuple, divisions_tuple, associated_data_tuple))
                
        unverified_tags_for_qualifier = self.wallet.get_unverified_tags_for_qualifier()
        for asset, h160_dict in unverified_tags_for_qualifier.items():
            for h160, d in h160_dict.items():
                txid = d['tx_hash']
                height = d['height']
                verifying_id = f't4q:{txid}'

                if await self._maybe_defer(txid, height, add_to_requested_set=False, alt_id=verifying_id): continue
                self.logger.info(f'attempting to verify tag for {asset}, {h160}')
                await self.taskgroup.spawn(self._verify_unverified_tags_for_qualifier(asset, h160, d))

        unverified_tags_for_h160 = self.wallet.get_unverified_tags_for_h160()
        for h160, asset_dict in unverified_tags_for_h160.items():
            for asset, d in asset_dict.items():
                txid = d['tx_hash']
                height = d['height']
                verifying_id = f't4h:{txid}'
                
                if await self._maybe_defer(txid, height, add_to_requested_set=False, alt_id=verifying_id): continue
                self.logger.info(f'attempting to verify tag for {h160}, {asset}')
                await self.taskgroup.spawn(self._verify_unverified_tags_for_h160(h160, asset, d))

        unverified_resticted_verifiers = self.wallet.get_unverified_restricted_verifier_strings()
        for asset, d in unverified_resticted_verifiers.items():
            txid = d['tx_hash']
            height = d['height']
            verifying_id = f'rs:{txid}'
            
            if await self._maybe_defer(txid, height, add_to_requested_set=False, alt_id=verifying_id): continue
            self.logger.info(f'attempting to verify restricted verifier for {asset}: {d["string"]}')
            await self.taskgroup.spawn(self._verify_unverified_restricted_verifier(asset, d))

        unverified_resticted_freezes = self.wallet.get_unverified_restricted_freezes()
        for asset, d in unverified_resticted_freezes.items():
            txid = d['tx_hash']
            height = d['height']
            verifying_id = f'rf:{txid}'

            if await self._maybe_defer(txid, height, add_to_requested_set=False, alt_id=verifying_id): continue
            self.logger.info(f'attempting to verify restricted freeze for {asset}: {d["frozen"]}')
            await self.taskgroup.spawn(self._verify_unverified_restricted_freeze(asset, d))

        unverified_broadcasts = self.wallet.get_unverified_broadcasts()
        for asset, d1 in unverified_broadcasts.items():
            for tx_hash, d2 in d1.items():
                height = d2['height']
                verifying_id = f'b:{tx_hash}'

                if await self._maybe_defer(tx_hash, height, add_to_requested_set=False, alt_id=verifying_id): continue
                self.logger.info(f'attempting to verify broadcast for {asset}: {tx_hash}')
                await self.taskgroup.spawn(self._verify_unverified_broadcast(asset, tx_hash, d2))

    async def _verify_unverified_broadcast(self, asset: str, tx_hash: str, d):
        height = d['height']

        verifying_id = f'b:{tx_hash}'
        self.verifying.add(verifying_id)
        try:
            await self._request_and_verify_single_proof(tx_hash, height, quick_return=True)
            tx = self.wallet.get_transaction(tx_hash)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(tx_hash)
                finally:
                    self._requests_answered += 1
                tx = Transaction(raw_tx)
            idx = d['tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx].scriptpubkey)
            if _type := asset_info.get_type() != AssetVoutType.TRANSFER:
                raise AssetException(f'bad asset type: {_type}')
            if asset_info.asset != asset:
                raise AssetException(f'bad asset: {asset}')
            if asset_info.asset_memo != base_decode(d['data'], base=58):
                raise AssetException(f'bad data: {asset_info.asset_memo}')
            if asset_info.asset_memo_timestamp != d['expiration']:
                raise AssetException(f'bad timestamp: {asset_info.asset_memo_timestamp}')
            for input in tx.inputs():

                in_txid = input.prevout.txid.hex()
                in_tx = self.wallet.get_transaction(in_txid)
                if not in_tx:
                    self._requests_sent += 1
                    try:
                        async with self._network_request_semaphore:
                            raw_tx = await self.interface.get_transaction(in_txid)
                    finally:
                        self._requests_answered += 1
                    in_tx = Transaction(raw_tx)

                if in_tx.outputs()[input.prevout.out_idx].address == tx.outputs()[idx].address and \
                    in_tx.outputs()[input.prevout.out_idx].asset == tx.outputs()[idx].asset:
                    break
            else:
                raise AssetException(f'no same vin address found')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
            import traceback
            traceback.print_exc()
            self.logger.info(f'bad broadcast {asset} {d["data"]}: {repr(e)}')
            self.wallet.remove_unverified_broadcast(asset, tx_hash, height)
            raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)

        self.logger.info(f'verified broadcast for {asset} {d["data"]}')
        self.wallet.add_verified_broadcast(asset, tx_hash, d)

    async def _verify_unverified_restricted_freeze(self, asset: str, d):
        txid = d['tx_hash']
        height = d['height']

        verifying_id = f'rf:{txid}'
        self.verifying.add(verifying_id)
        try:
            await self._request_and_verify_single_proof(txid, height, quick_return=True)
            tx = self.wallet.get_transaction(txid)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(txid)
                    tx = Transaction(raw_tx)
                finally:
                    self._requests_answered += 1
            idx = d['tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx].scriptpubkey)
            if _type := asset_info.get_type() != AssetVoutType.FREEZE:
                raise AssetException(f'bad asset type: {_type}')
            if asset_info.asset != asset:
                raise AssetException(f'bad asset: {asset}')
            if asset_info.flag != d['frozen']:
                raise AssetException(f'bad flag: {d["frozen"]}')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
            self.logger.info(f'bad freeze {asset} {d["frozen"]}: {repr(e)}')
            self.wallet.remove_unverified_restricted_freeze(asset, height)
            raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)

        self.logger.info(f'verified freeze for {asset} {d["frozen"]}')
        self.wallet.add_verified_restricted_freeze(asset, d)

    async def _verify_unverified_restricted_verifier(self, asset: str, d):
        txid = d['tx_hash']
        height = d['height']

        verifying_id = f'rs:{txid}'
        self.verifying.add(verifying_id)
        try:
            await self._request_and_verify_single_proof(txid, height, quick_return=True)
            tx = self.wallet.get_transaction(txid)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(txid)
                    tx = Transaction(raw_tx)
                finally:
                    self._requests_answered += 1
            idx_qual = d['qualifying_tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx_qual].scriptpubkey)
            if _type := asset_info.get_type() != AssetVoutType.VERIFIER:
                raise AssetException(f'bad asset type: {_type}')
            if d['string'] != asset_info.verifier_string:
                raise AssetException(f'verifier string mismatch: {d["string"]} vs {asset_info.verifier_string}')
            idx_restricted = d['restricted_tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx_restricted].scriptpubkey)
            if _type := asset_info.get_type() not in (AssetVoutType.CREATE, AssetVoutType.REISSUE):
                raise AssetException(f'bad asset type: {_type}')
            if asset_info.asset != asset:
                raise AssetException(f'bad asset: {asset}')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
            self.logger.info(f'bad verifier tag {asset} {d["string"]}: {repr(e)}')
            self.wallet.remove_unverified_restricted_verifier_string(asset, height)
            raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)
            
        self.logger.info(f'verified verifier for {asset} {d["string"]}')
        self.wallet.add_verified_restricted_verifier_string(asset, d)

    async def _verify_unverified_asset_metadata(
            self, 
            asset: str, 
            metadata: AssetMetadata, 
            source: Tuple[TxOutpoint, int],
            divisions_source: Tuple[TxOutpoint, int] | None, 
            associated_data_source: Tuple[TxOutpoint, int] | None):
        
        verifying_id = f'm:{asset}'
        self.verifying.add(verifying_id)

        verified_metadata = self.wallet.db.get_verified_asset_metadata(asset)
        if verified_metadata:
            if metadata.sats_in_circulation < verified_metadata.sats_in_circulation:
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect('Sats are less than verified sats')
        
        verified_metadata_source = self.wallet.db.get_verified_asset_metadata_base_source(asset)
        if verified_metadata_source:
            _, verified_height = verified_metadata_source
            if source[1] < verified_height:
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect('New base height is less than verified base height')

        if divisions_source:
            if divisions_source[1] > source[1]:
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect('Divisions source is over base source')
            
        if associated_data_source:
            if associated_data_source[1] > source[1]:
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect('Associated data source is over base source')

        if divisions_source:
            source_txid = divisions_source[0].txid.hex()
            source_idx = divisions_source[0].out_idx
            source_height = divisions_source[1]
            try:
                await self._request_and_verify_single_proof(source_txid, source_height, quick_return=True)
                tx = self.wallet.get_transaction(source_txid)
                if not tx:
                    self._requests_sent += 1
                    try:
                        async with self._network_request_semaphore:
                            raw_tx = await self.interface.get_transaction(source_txid)
                        tx = Transaction(raw_tx)
                    finally:
                        self._requests_answered += 1
                asset_info = get_asset_info_from_script(tx.outputs()[source_idx].scriptpubkey)
                if not isinstance(asset_info, MetadataAssetVoutInformation):
                    raise AssetException('No metadata at this outpoint!(1)')
                if asset_info.asset != asset:
                    raise AssetException('Not our asset!(1)')
                if asset_info.divisions != metadata.divisions:
                    raise AssetException('Bad division amount!')
            except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
                self.logger.info(f'bad asset metadata for {asset} (1): {repr(e)}')
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect(e) from e
            
        if associated_data_source:
            source_txid = associated_data_source[0].txid.hex()
            source_idx = associated_data_source[0].out_idx
            source_height = associated_data_source[1]
            try:
                await self._request_and_verify_single_proof(source_txid, source_height, quick_return=True)
                tx = self.wallet.get_transaction(source_txid)
                if not tx:
                    self._requests_sent += 1
                    try:
                        async with self._network_request_semaphore:
                            raw_tx = await self.interface.get_transaction(source_txid)
                        tx = Transaction(raw_tx)
                    finally:
                        self._requests_answered += 1
                asset_info = get_asset_info_from_script(tx.outputs()[source_idx].scriptpubkey)
                if not isinstance(asset_info, MetadataAssetVoutInformation):
                    raise AssetException('No metadata at this outpoint!(2)')
                if asset_info.asset != asset:
                    raise AssetException('Not our asset!(2)')
                if asset_info.associated_data != metadata.associated_data:
                    raise AssetException('Bad associated data!')
            except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
                self.logger.info(f'bad asset metadata for {asset} (2): {repr(e)}')
                self.wallet.remove_unverified_asset_metadata(asset, source[1])
                raise GracefulDisconnect(e) from e
            
        source_txid = source[0].txid.hex()
        source_idx = source[0].out_idx
        source_height = source[1]
        try:
            await self._request_and_verify_single_proof(source_txid, source_height, quick_return=True)
            tx = self.wallet.get_transaction(source_txid)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(source_txid)
                    tx = Transaction(raw_tx)
                finally:
                    self._requests_answered += 1
            asset_info = get_asset_info_from_script(tx.outputs()[source_idx].scriptpubkey)
            if not isinstance(asset_info, MetadataAssetVoutInformation):
                if not isinstance(asset_info, OwnerAssetVoutInformation):
                    raise AssetException('No metadata at this outpoint!(3)')
                if asset_info.asset != asset:
                    raise AssetException('Not our asset!(4)')
                if metadata.divisions != 0:
                    raise AssetException('Bad divisions! (3)')
                if metadata.associated_data is not None:
                    raise AssetException('Bad associated data! (3)')
                if metadata.reissuable:
                    raise AssetException('Bad reissuable (2)')
            else:
                if asset_info.asset != asset:
                    raise AssetException('Not our asset!(3)')
                if asset_info.divisions != metadata.divisions and not divisions_source:
                    raise AssetException('Bad divisions! (2)')
                if asset_info.associated_data != metadata.associated_data and not associated_data_source:
                    raise AssetException('Bad associated data! (2)')
                if asset_info.reissuable != metadata.reissuable:
                    raise AssetException('Bad reissuable')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
            self.logger.info(f'bad asset metadata for {asset} (3): {repr(e)}')
            self.wallet.remove_unverified_asset_metadata(asset, source[1])
            raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)

        self.logger.info(f'verified metadata for {asset}')
        self.wallet.add_verified_asset_metadata(asset, metadata, source, divisions_source, associated_data_source)

    async def _verify_unverified_tags_for_qualifier(self, asset, h160, d):
        txid = d['tx_hash']
        height = d['height']

        verifying_id = f't4q:{txid}'
        self.verifying.add(verifying_id)
        try:
            await self._request_and_verify_single_proof(txid, height, quick_return=True)
            tx = self.wallet.get_transaction(txid)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(txid)
                    tx = Transaction(raw_tx)
                finally:
                    self._requests_answered += 1
            idx = d['tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx].scriptpubkey)
            if _type := asset_info.get_type() != AssetVoutType.NULL:
                raise AssetException(f'bad asset type: {_type}')
            if h160 != asset_info.h160:
                raise AssetException(f'h160 mismatch: {h160} vs {asset_info.h160}')
            if asset != asset_info.asset:
                raise AssetException(f'asset mismatch: {asset} vs {asset_info.asset}')
            if d['flag'] != asset_info.flag:
                raise AssetException(f'bad flag: {asset_info.flag}')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
                self.logger.info(f'bad qualifier tag {asset} {h160}: {repr(e)}')
                self.wallet.remove_unverified_tag_for_qualifier(asset, h160, height)
                raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)
            
        self.logger.info(f'verified tag for {asset} {h160}')
        self.wallet.add_verified_tag_for_qualifier(asset, h160, d)


    async def _verify_unverified_tags_for_h160(self, h160, asset, d):
        txid = d['tx_hash']
        height = d['height']

        verifying_id = f't4h:{txid}'
        self.verifying.add(verifying_id)
        try:
            await self._request_and_verify_single_proof(txid, height, quick_return=True)
            tx = self.wallet.get_transaction(txid)
            if not tx:
                self._requests_sent += 1
                try:
                    async with self._network_request_semaphore:
                        raw_tx = await self.interface.get_transaction(txid)
                    tx = Transaction(raw_tx)
                finally:
                    self._requests_answered += 1
            idx = d['tx_pos']
            asset_info = get_asset_info_from_script(tx.outputs()[idx].scriptpubkey)
            if _type := asset_info.get_type() != AssetVoutType.NULL:
                raise AssetException(f'bad asset type: {_type}')
            if h160 != asset_info.h160:
                raise AssetException(f'h160 mismatch: {h160} vs {asset_info.h160}')
            if asset != asset_info.asset:
                raise AssetException(f'asset mismatch: {asset} vs {asset_info.asset}')
            if d['flag'] != asset_info.flag:
                raise AssetException(f'bad flag: {asset_info.flag}')
        except (aiorpcx.jsonrpc.RPCError, RequestCorrupted, AssetException, IndexError) as e:
                self.logger.info(f'bad qualifier tag {h160} {asset}: {repr(e)}')
                self.wallet.remove_unverified_tag_for_h160(h160, asset, height)
                raise GracefulDisconnect(e) from e
        finally:
            self.verifying.discard(verifying_id)
            
        self.logger.info(f'verified tag for {h160} {asset}')
        self.wallet.add_verified_tag_for_h160(h160, asset, d)


    async def _verify_unverified_transaction(self, tx_hash, tx_height):
        try:
            pos, header = await self._request_and_verify_single_proof(tx_hash, tx_height)
        except aiorpcx.jsonrpc.RPCError:
            self.logger.info(f'tx {tx_hash} not at height {tx_height}')
            self.wallet.remove_unverified_tx(tx_hash, tx_height)
            return
        
        header_hash = hash_header(header)
        tx_info = TxMinedInfo(height=tx_height,
                            timestamp=header.get('timestamp'),
                            txpos=pos,
                            header_hash=header_hash)
        self.wallet.add_verified_tx(tx_hash, tx_info)


    async def _request_and_verify_single_proof(self, tx_hash, tx_height, *, quick_return=False):
        if quick_return and tx_hash in self.merkle_roots:
            return
        self.logger.info(f'requesting merkle {tx_hash}')
        try:
            self._requests_sent += 1
            async with self._network_request_semaphore:
                merkle = await self.interface.get_merkle_for_transaction(tx_hash, tx_height)
        finally:
            self.requested_merkle.discard(tx_hash)
            self._requests_answered += 1
        # Verify the hash of the server-provided merkle branch to a
        # transaction matches the merkle root of its block
        if tx_height != merkle.get('block_height'):
            self.logger.info('requested tx_height {} differs from received tx_height {} for txid {}'
                             .format(tx_height, merkle.get('block_height'), tx_hash))
        tx_height = merkle.get('block_height')
        pos = merkle.get('pos')
        merkle_branch = merkle.get('merkle')
        # we need to wait if header sync/reorg is still ongoing, hence lock:
        async with self.network.bhi_lock:
            header = self.network.blockchain().read_header(tx_height)
        try:
            verify_tx_is_in_block(tx_hash, merkle_branch, pos, header, tx_height)
        except MerkleVerificationFailure as e:
            if self.network.config.NETWORK_SKIPMERKLECHECK:
                self.logger.info(f"skipping merkle proof check {tx_hash}")
            else:
                self.logger.info(repr(e))
                raise GracefulDisconnect(e) from e
        # we passed all the tests
        self.merkle_roots[tx_hash] = header.get('merkle_root')
        self.logger.info(f"verified {tx_hash}")    

        return pos, header
        
    @classmethod
    def hash_merkle_root(cls, merkle_branch: Sequence[str], tx_hash: str, leaf_pos_in_tree: int):
        """Return calculated merkle root."""
        try:
            h = hash_decode(tx_hash)
            merkle_branch_bytes = [hash_decode(item) for item in merkle_branch]
            leaf_pos_in_tree = int(leaf_pos_in_tree)  # raise if invalid
        except Exception as e:
            raise MerkleVerificationFailure(e)
        if leaf_pos_in_tree < 0:
            raise MerkleVerificationFailure('leaf_pos_in_tree must be non-negative')
        index = leaf_pos_in_tree
        for item in merkle_branch_bytes:
            if len(item) != 32:
                raise MerkleVerificationFailure('all merkle branch items have to 32 bytes long')
            inner_node = (item + h) if (index & 1) else (h + item)
            cls._raise_if_valid_tx(inner_node.hex())
            h = sha256d(inner_node)
            index >>= 1
        if index != 0:
            raise MerkleVerificationFailure(f'leaf_pos_in_tree too large for branch')
        return hash_encode(h)

    @classmethod
    def _raise_if_valid_tx(cls, raw_tx: str):
        # If an inner node of the merkle proof is also a valid tx, chances are, this is an attack.
        # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html
        # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20180609/9f4f5b1f/attachment-0001.pdf
        # https://bitcoin.stackexchange.com/questions/76121/how-is-the-leaf-node-weakness-in-merkle-trees-exploitable/76122#76122
        tx = Transaction(raw_tx)
        try:
            tx.deserialize()
        except Exception:
            pass
        else:
            raise InnerNodeOfSpvProofIsValidTx()

    async def _maybe_undo_verifications(self):
        old_chain = self.blockchain
        cur_chain = self.network.blockchain()
        if cur_chain != old_chain:
            self.blockchain = cur_chain
            above_height = cur_chain.get_height_of_last_common_block_with_chain(old_chain)
            self.logger.info(f"undoing verifications above height {above_height}")
            tx_hashes = self.wallet.undo_verifications(self.blockchain, above_height)
            for tx_hash in tx_hashes:
                self.logger.info(f"redoing {tx_hash}")
                self.remove_spv_proof_for_tx(tx_hash)

    def remove_spv_proof_for_tx(self, tx_hash):
        self.merkle_roots.pop(tx_hash, None)
        self.requested_merkle.discard(tx_hash)

    def is_up_to_date(self):
        #print(f'{self.requested_merkle=}')
        #print(f'{self.wallet.unverified_tx=}')
        #print(f'{self.wallet.unverified_asset_metadata=}')
        #print(f'{self.wallet.unverified_tags_for_qualifier=}')
        #print(f'{self.wallet.unverified_tags_for_h160=}')
        #print(f'{self.wallet.unverified_verifier_for_restricted=}')
        #print(f'{self.wallet.unverified_freeze_for_restricted=}')
        #print(f'{self.wallet.unverified_broadcast=}')

        return (not self.requested_merkle
                and not self.wallet.unverified_tx
                and not self.wallet.unverified_asset_metadata
                and not self.wallet.unverified_tags_for_qualifier
                and not self.wallet.unverified_tags_for_h160
                and not self.wallet.unverified_verifier_for_restricted
                and not self.wallet.unverified_freeze_for_restricted
                and not self.wallet.unverified_broadcast)

def verify_tx_is_in_block(tx_hash: str, merkle_branch: Sequence[str],
                          leaf_pos_in_tree: int, block_header: Optional[dict],
                          block_height: int) -> None:
    """Raise MerkleVerificationFailure if verification fails."""
    if not block_header:
        raise MissingBlockHeader("merkle verification failed for {} (missing header {})"
                                 .format(tx_hash, block_height))
    if len(merkle_branch) > 30:
        raise MerkleVerificationFailure(f"merkle branch too long: {len(merkle_branch)}")
    calc_merkle_root = SPV.hash_merkle_root(merkle_branch, tx_hash, leaf_pos_in_tree)
    if block_header.get('merkle_root') != calc_merkle_root:
        raise MerkleRootMismatch("merkle verification failed for {} ({} != {})".format(
            tx_hash, block_header.get('merkle_root'), calc_merkle_root))
