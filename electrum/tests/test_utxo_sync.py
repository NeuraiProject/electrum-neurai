import hashlib
from unittest import mock

from aiorpcx.jsonrpc import RPCError

from electrum import keystore, storage, utxo_sync, wallet
from electrum.simple_config import SimpleConfig
from electrum.transaction import PartialTransaction, PartialTxInput, PartialTxOutput, Transaction, TxOutpoint
from electrum.utxo_sync import UtxoSetError, to_hex, utxo_hash
from electrum.wallet import Standard_Wallet

from . import ElectrumTestCase


def utxo(n: int, vout: int, height: int, value: int, asset=None) -> dict:
    return {'tx_hash': f'{n:02x}' * 32, 'tx_pos': vout, 'height': height, 'value': value, 'asset': asset}


def outpoint(u: dict) -> dict:
    return {'tx_hash': u['tx_hash'], 'tx_pos': u['tx_pos']}


def h(u: dict) -> int:
    return utxo_hash(u['tx_hash'], u['tx_pos'], u['height'], u['value'], u['asset'])


def changes_hash(added, removed) -> str:
    return to_hex(sum(map(h, added)) - sum(map(h, removed)))


class FakeInterface:
    """Answers utxo_sync and utxo_chunk like electrs-neurai would."""

    def __init__(self):
        self.replies = {}  # from_block -> reply
        self.chunks = {}  # id -> chunks
        self.expired = 0  # utxo_chunk calls to answer with error 10

    async def utxo_sync(self, sh, from_block):
        return self.replies[from_block]

    async def utxo_chunk(self, sh, reply_id, index):
        if self.expired:
            self.expired -= 1
            raise RPCError(10, 'snapshot expired')
        return self.chunks[reply_id][index]


def reply(*, from_block, block, height, utxos, chunks, reply_id='r1', mempool=None, base_hash=0):
    """A utxo_sync reply leading to `utxos`, with `chunks` of changes."""
    total = base_hash + sum(int(changes_hash(c['added'], c['removed_utxos']), 16) for c in chunks)
    result = {
        'from_block': from_block,
        'height': height,
        'block_hash': block,
        'count': len(utxos),
        'set_hash': to_hex(total),
        'chunks': [changes_hash(c['added'], c['removed_utxos']) for c in chunks],
        'id': None if len(chunks) == 1 else reply_id,
        'mempool': mempool or {'added': [], 'spent': []},
    }
    plain = [{'added': c['added'], 'removed': [outpoint(u) for u in c['removed_utxos']]} for c in chunks]
    if len(chunks) == 1:
        result.update(plain[0])
    return result, plain


class TestUtxoSync(ElectrumTestCase):

    def test_hash_matches_the_spec(self):
        txid = '5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b'
        text = f'{txid}:1:123456:5000000:'
        expected = int.from_bytes(hashlib.sha256(text.encode()).digest(), 'big')
        self.assertEqual(expected, utxo_hash(txid, 1, 123456, 5000000, None))
        text = f'{txid}:1:123456:5000000:TOKEN/SUB'
        expected = int.from_bytes(hashlib.sha256(text.encode()).digest(), 'big')
        self.assertEqual(expected, utxo_hash(txid, 1, 123456, 5000000, 'TOKEN/SUB'))
        self.assertEqual('0' * 64, to_hex(0))
        self.assertEqual('f' * 64, to_hex(-1))

    async def test_whole_set_in_chunks_then_changes(self):
        sh = 'aa' * 32
        a, b, c = utxo(1, 0, 10, 100), utxo(2, 1, 11, 200, 'TOKEN'), utxo(3, 0, 12, 300)
        iface = FakeInterface()
        iface.replies[None], iface.chunks['r1'] = reply(
            from_block=None, block='01' * 32, height=12, utxos=[a, b, c],
            chunks=[{'added': [a, b], 'removed_utxos': []}, {'added': [c], 'removed_utxos': []}])
        stored = await utxo_sync.sync(iface, sh, None)
        self.assertEqual(3, len(stored['utxos']))
        self.assertEqual([11, 200, 'TOKEN', None], stored['utxos'][f"{b['tx_hash']}:1"])
        self.assertEqual(to_hex(h(a) + h(b) + h(c)), stored['set_hash'])
        self.assertEqual(stored['set_hash'], stored['status'])

        # a block spends `a` and pays `d`; the mempool spends `b` and pays `m`
        d = utxo(4, 0, 13, 400)
        m = utxo(5, 2, 0, 50)
        iface.replies['01' * 32], _ = reply(
            from_block='01' * 32, block='02' * 32, height=13, utxos=[b, c, d],
            chunks=[{'added': [d], 'removed_utxos': [a]}], base_hash=h(a) + h(b) + h(c),
            mempool={'added': [m], 'spent': [outpoint(b)]})
        stored = await utxo_sync.sync(iface, sh, stored)
        self.assertEqual({f"{u['tx_hash']}:{u['tx_pos']}" for u in (b, c, d)}, set(stored['utxos']))
        self.assertEqual(to_hex(h(b) + h(c) + h(d)), stored['set_hash'])
        self.assertEqual({f"{m['tx_hash']}:2": [50, None]}, stored['mempool_added'])
        # the status is the hash of the spendable view
        self.assertEqual(to_hex(h(c) + h(d) + h(m)), stored['status'])
        self.assertEqual(13, utxo_sync.txid_heights([stored])[d['tx_hash']])
        self.assertEqual(0, utxo_sync.txid_heights([stored])[m['tx_hash']])

    async def test_replies_that_dont_add_up(self):
        sh = 'aa' * 32
        a, b = utxo(1, 0, 10, 100), utxo(2, 0, 11, 200)

        async def sync_with(changes):
            iface = FakeInterface()
            iface.replies[None], _ = reply(from_block=None, block='01' * 32, height=11, utxos=[a, b],
                                           chunks=[{'added': [a, b], 'removed_utxos': []}])
            iface.replies[None].update(changes)
            return await utxo_sync.sync(iface, sh, None)

        await sync_with({})
        with self.assertRaises(UtxoSetError):  # a chunk hash
            await sync_with({'chunks': [changes_hash([a], [])], 'set_hash': changes_hash([a], [])})
        with self.assertRaises(UtxoSetError):  # the total
            await sync_with({'set_hash': changes_hash([a], [])})
        with self.assertRaises(UtxoSetError):  # the count
            await sync_with({'count': 3})
        with self.assertRaises(UtxoSetError):  # an unconfirmed UTXO among the confirmed ones
            await sync_with({'added': [a, utxo(2, 0, 0, 200)]})
        with self.assertRaises(UtxoSetError):  # the mempool spends something else
            await sync_with({'mempool': {'added': [], 'spent': [outpoint(utxo(9, 0, 1, 1))]}})

    async def test_changes_from_another_block_or_of_unknown_utxos(self):
        sh = 'aa' * 32
        a = utxo(1, 0, 10, 100)
        iface = FakeInterface()
        iface.replies[None], _ = reply(from_block=None, block='01' * 32, height=10, utxos=[a],
                                       chunks=[{'added': [a], 'removed_utxos': []}])
        stored = await utxo_sync.sync(iface, sh, None)
        # changes from a block the client didn't ask for
        iface.replies['01' * 32], _ = reply(from_block='03' * 32, block='02' * 32, height=11, utxos=[a],
                                            chunks=[{'added': [], 'removed_utxos': []}], base_hash=h(a))
        with self.assertRaises(UtxoSetError):
            await utxo_sync.sync(iface, sh, stored)
        # removing a UTXO the client doesn't have
        x = utxo(7, 0, 5, 1)
        iface.replies['01' * 32], _ = reply(from_block='01' * 32, block='02' * 32, height=11, utxos=[a],
                                            chunks=[{'added': [], 'removed_utxos': [x]}], base_hash=h(a) + h(x))
        with self.assertRaises(UtxoSetError):
            await utxo_sync.sync(iface, sh, stored)
        # the stored set is untouched by failed syncs
        self.assertEqual([10, 100, None, None], stored['utxos'][f"{a['tx_hash']}:0"])

    async def test_expired_chunks_are_asked_again(self):
        sh = 'aa' * 32
        a, b = utxo(1, 0, 10, 100), utxo(2, 0, 11, 200)
        iface = FakeInterface()
        iface.replies[None], iface.chunks['r1'] = reply(
            from_block=None, block='01' * 32, height=11, utxos=[a, b],
            chunks=[{'added': [a], 'removed_utxos': []}, {'added': [b], 'removed_utxos': []}])
        iface.expired = 1
        stored = await utxo_sync.sync(iface, sh, None)
        self.assertEqual(2, len(stored['utxos']))
        iface.expired = 100
        with self.assertRaises(RPCError):
            await utxo_sync.sync(iface, sh, None)


class TestUtxoModeWallet(ElectrumTestCase):
    """A coin known from a UTXO set is spent like one known from the history."""

    SEED = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def create_wallet(self):
        db = storage.WalletDB('', storage=None, manual_upgrades=False)
        db.put('keystore', keystore.from_seed(self.SEED, '', False).dump())
        db.put('gap_limit', 2)
        w = Standard_Wallet(db, config=self.config)
        w.synchronize()
        return w

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_utxo_set_coins_spend_like_history_coins(self, mock_save_db):
        history_wallet = self.create_wallet()
        utxo_wallet = self.create_wallet()
        address = history_wallet.get_receiving_addresses()[0]
        value = 10_000_000_000

        # a transaction paying `address` (its input is made up: not checked)
        funding = PartialTransaction.from_io(
            [PartialTxInput(prevout=TxOutpoint(txid=bytes(range(32)), out_idx=1))],
            [PartialTxOutput.from_address_and_value(address, value)],
            locktime=0, version=2)
        funding = Transaction(funding.serialize_to_network(include_sigs=False))
        txid = funding.txid()

        # known from the history...
        history_wallet.adb.receive_tx_callback(txid, funding, 100)
        # ... or from a UTXO set
        utxos = {f'{txid}:0': [100, value, None, False]}
        utxo_set = {
            'block_hash': '11' * 32, 'height': 150, 'set_hash': to_hex(utxo_sync.set_hash(utxos)),
            'utxos': utxos, 'mempool_added': {}, 'mempool_spent': [],
        }
        utxo_set['status'] = utxo_sync.status(utxo_set)
        utxo_wallet.adb.receive_utxo_set_callback(address, utxo_set)

        self.assertEqual(history_wallet.get_balance(), utxo_wallet.get_balance())
        self.assertEqual((value, 0, 0), utxo_wallet.get_balance())
        self.assertTrue(utxo_wallet.adb.is_used(address))
        self.assertEqual(100, utxo_wallet.adb.get_tx_height(txid).height)
        coins = utxo_wallet.get_spendable_coins(None)
        self.assertEqual([f'{txid}:0'], [c.prevout.to_str() for c in coins])

        # the same payment, signed the same way
        destination = 'NbiD2ZWQx79GETVRmxxPXUD8T9wMXfLhzo'
        signed = []
        for w in (history_wallet, utxo_wallet):
            outputs = [PartialTxOutput.from_address_and_value(destination, 2_500_000_000)]
            tx = w.mktx(outputs=outputs, password=None, fee=10_000, tx_version=2, rbf=False)
            self.assertTrue(tx.is_complete())
            signed.append(tx)
        self.assertEqual(signed[0].serialize(), signed[1].serialize())

        # spent by our own transaction: not spendable anymore, its change is
        utxo_wallet.adb.add_transaction(signed[1])
        self.assertEqual([], [c for c in utxo_wallet.get_spendable_coins(None)
                              if c.prevout.to_str() == f'{txid}:0'])

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_mempool_part_and_coinbase_maturity(self, mock_save_db):
        w = self.create_wallet()
        address = w.get_receiving_addresses()[0]
        utxos = {
            'aa' * 32 + ':0': [100, 5_000, None, True],     # coinbase, immature at height 150
            'bb' * 32 + ':1': [50, 7_000, None, None],      # old enough not to matter
            'cc' * 32 + ':2': [140, 9_000, 'TOKEN', False],  # an asset
        }
        utxo_set = {
            'block_hash': '11' * 32, 'height': 150, 'set_hash': to_hex(utxo_sync.set_hash(utxos)),
            'utxos': utxos,
            'mempool_added': {'dd' * 32 + ':0': [1_000, None]},
            'mempool_spent': ['bb' * 32 + ':1'],
        }
        utxo_set['status'] = utxo_sync.status(utxo_set)
        w.db.put('stored_height', 150)
        w.adb.receive_utxo_set_callback(address, utxo_set)
        # confirmed: none (the old coin is spent in the mempool), unconfirmed:
        # the mempool's output, unmatured: the coinbase
        self.assertEqual((0, 1_000, 5_000), w.get_balance())
        balances = w.adb.get_balance([address], asset_aware=True)
        self.assertEqual((9_000, 0, 0), balances['TOKEN'])
        self.assertEqual(0, w.adb.get_tx_height('dd' * 32).height)
        self.assertNotIn('bb' * 32 + ':1', [c.prevout.to_str() for c in w.get_spendable_coins(None)])
