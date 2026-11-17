import asyncio
from unittest import mock

from aiorpcx.jsonrpc import RPCError

from electrum import keystore, recent_history, storage, utxo_sync, wallet
from electrum.address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_UNCONFIRMED
from electrum.interface import RequestCorrupted, _assert_recent_history
from electrum.logging import get_logger
from electrum.recent_history import MAX_ENTRIES, RECENT_HISTORY_UNAVAILABLE, RecentHistoryError
from electrum.simple_config import SimpleConfig
from electrum.synchronizer import Synchronizer
from electrum.transaction import PartialTransaction, PartialTxInput, PartialTxOutput, Transaction, TxOutpoint
from electrum.utxo_sync import to_hex
from electrum.wallet import Standard_Wallet

from . import ElectrumTestCase


def txid(n: int) -> str:
    return n.to_bytes(32, 'big').hex()


def block_hash(height: int, fork: int = 0) -> str:
    return (height + fork * 10 ** 9).to_bytes(32, 'little').hex()


class FakeServer:
    """Keeps the recent history of a scripthash like electrs-neurai: the last
    MAX_ENTRIES confirmed transactions and the mempool ones, newest first."""

    def __init__(self):
        self.blocks = {}  # height -> [entry] in block order
        self.mempool = []  # newest first
        self.height = 0
        self.fork = 0
        self.calls = []  # (offset, limit)
        self.before_reply = None  # called before each reply
        self.entries_of_all = 0  # transactions of the scripthash, kept or not

    def tip_hash(self) -> str:
        return block_hash(self.height, self.fork)

    def add_block(self, entries):
        self.height += 1
        self.blocks[self.height] = [dict(e, height=self.height) for e in entries]
        self.entries_of_all += len(entries)

    def confirmed(self):
        out = []
        for height in sorted(self.blocks, reverse=True):
            out += list(reversed(self.blocks[height]))
        return out[:MAX_ENTRIES]

    def all_entries(self):
        return self.mempool + self.confirmed()

    async def supports_recent_history(self):
        return True

    async def get_recent_history(self, sh, offset, limit):
        if self.before_reply:
            self.before_reply(self)
        self.calls.append((offset, limit))
        entries = self.all_entries()
        reply = {
            'height': self.height,
            'block_hash': self.tip_hash(),
            'total': len(entries),
            'complete': self.entries_of_all <= MAX_ENTRIES,
            'entries': entries[offset:offset + limit],
        }
        _assert_recent_history(reply, offset=offset, limit=limit)
        return reply


def entry(n: int, value: int, assets=None, height=0) -> dict:
    return {'tx_hash': txid(n), 'height': height, 'value': value, 'assets': assets or {}}


def stored_form(entries):
    return [recent_history.entry_from_reply(e) for e in entries]


class TestRecentHistorySync(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.server = FakeServer()
        self.chain = {}  # our headers: height -> hash

    def is_in_chain(self, height, block_hash):
        return self.chain.get(height) == block_hash

    def our_chain_follows(self):
        self.chain = {h: block_hash(h, self.server.fork) for h in range(1, self.server.height + 1)}

    async def sync(self, stored):
        self.server.calls = []
        recent = await recent_history.sync(self.server, 'aa' * 32, stored, is_in_chain=self.is_in_chain)
        self.assertEqual(stored_form(self.server.all_entries()), recent['entries'])
        self.assertEqual(self.server.height, recent['height'])
        self.assertEqual(self.server.tip_hash(), recent['block_hash'])
        return recent

    def mine(self, num_blocks, per_block=1, *, start=None):
        n = start if start is not None else self.server.entries_of_all + 1
        for _ in range(num_blocks):
            self.server.add_block([entry(n + i, 100 + n + i) for i in range(per_block)])
            n += per_block
        self.our_chain_follows()

    async def test_first_read_then_one_page_per_block(self):
        self.mine(1200)  # more than the server keeps
        self.server.mempool = [entry(9001, -5, {'TOKEN': 7}, height=-1), entry(9000, 30)]
        recent = await self.sync(None)
        self.assertEqual([(0, 50), (50, 500), (550, 500)], self.server.calls)
        self.assertEqual(MAX_ENTRIES + 2, len(recent['entries']))
        self.assertFalse(recent['complete'])
        self.assertEqual([txid(9001), -1, -5, [['TOKEN', 7]]], recent['entries'][0])
        self.assertEqual([txid(1200), 1200, 1300, []], recent['entries'][2])

        # a block confirms the mempool ones (in another order) and a new one
        self.server.mempool = []
        self.server.add_block([entry(9000, 30), entry(9002, 1), entry(9001, -5, {'TOKEN': 7})])
        self.our_chain_follows()
        recent = await self.sync(recent)
        self.assertEqual([(0, 50)], self.server.calls)
        self.assertEqual(MAX_ENTRIES, len(recent['entries']))
        self.assertEqual([txid(9001), 1201, -5, [['TOKEN', 7]]], recent['entries'][0])

        # a block without entries for us, and a new mempool entry
        self.server.add_block([])
        self.server.mempool = [entry(9003, -2)]
        self.our_chain_follows()
        recent = await self.sync(recent)
        self.assertEqual([(0, 50)], self.server.calls)

    async def test_many_blocks_while_offline(self):
        self.mine(300)
        recent = await self.sync(None)
        self.assertTrue(recent['complete'])
        self.assertEqual([(0, 50), (50, 500)], self.server.calls)
        self.mine(120, per_block=5)  # 600 new entries: more pages, until they reach ours
        recent = await self.sync(recent)
        self.assertEqual([(0, 50), (50, 500), (550, 500)], self.server.calls)
        self.assertTrue(recent['complete'])
        self.mine(250, per_block=5)  # more than MAX_ENTRIES new ones
        recent = await self.sync(recent)
        self.assertEqual([(0, 50), (50, 500), (550, 500)], self.server.calls)
        self.assertFalse(recent['complete'])

    async def test_reorg(self):
        self.mine(100)
        recent = await self.sync(None)
        # the last two blocks are replaced (one entry moves, one is gone)
        del self.server.blocks[100], self.server.blocks[99]
        self.server.height = 98
        self.server.fork = 1
        self.server.add_block([entry(100, 200)])
        self.server.add_block([entry(500, 7)])
        self.server.add_block([])
        self.our_chain_follows()
        recent = await self.sync(recent)  # all read again: our block is not in the chain anymore
        self.assertEqual([(0, 50), (50, 500)], self.server.calls)
        self.assertNotIn(txid(99), [e[0] for e in recent['entries']])
        # without a reorg of our block, entries that don't match what we keep are read again too
        recent['entries'][5][2] += 1
        self.server.add_block([entry(501, 7)])
        self.our_chain_follows()
        await self.sync(recent)
        self.assertEqual([(0, 50), (0, 50), (50, 500)], self.server.calls)

    async def test_server_with_more_old_entries(self):
        # e.g. the server kept fewer entries after a reorg, and has them all again
        self.mine(300)
        recent = await self.sync(None)
        recent['entries'] = recent['entries'][:200]
        self.mine(2)
        await self.sync(recent)
        self.assertEqual([(0, 50), (0, 50), (50, 500)], self.server.calls)

    async def test_tip_moving_between_pages(self):
        self.mine(200)

        def new_block_once(server):
            if len(server.calls) == 1 and server.height == 200:
                server.add_block([entry(777, 1)])
        self.server.before_reply = new_block_once
        recent = await self.sync(None)
        self.assertEqual([(0, 50), (50, 500), (0, 50), (50, 500)], self.server.calls)
        self.assertEqual(txid(777), recent['entries'][0][0])

        # always moving: given up, nothing kept
        self.server.before_reply = lambda server: server.add_block([entry(server.entries_of_all + 1000, 1)])
        with self.assertRaises(RecentHistoryError):
            await recent_history.sync(self.server, 'aa' * 32, None, is_in_chain=self.is_in_chain)

    async def test_progress_is_counted(self):
        self.mine(60)
        counted = []
        await recent_history.sync(self.server, 'aa' * 32, None, is_in_chain=self.is_in_chain,
                                  progress=lambda sent, answered: counted.append((sent, answered)))
        self.assertEqual([(1, 0), (0, 1), (1, 0), (0, 1)], counted)

    async def test_feature(self):
        from electrum.interface import Interface
        iface = Interface.__new__(Interface)
        for features, expected in (({'recent_history': 1}, True), ({'recent_history': 2}, True),
                                   ({'recent_history': True}, False), ({}, False), ({'recent_history': '1'}, False)):
            iface._server_features = features
            self.assertEqual(expected, await iface.supports_recent_history(), features)

    def test_replies_are_checked(self):
        good = {'height': 10, 'block_hash': 'bb' * 32, 'total': 3, 'complete': True,
                'entries': [entry(3, 1, height=0), entry(2, -1, {'A': 1}, height=10), entry(1, 5, height=4)]}
        _assert_recent_history(good, offset=0, limit=50)

        def bad(**changes):
            reply = dict(good, **changes)
            with self.assertRaises(RequestCorrupted):
                _assert_recent_history(reply, offset=changes.pop('_offset', 0), limit=changes.pop('_limit', 50))
        bad(entries=[entry(2, -1, height=10), entry(3, 1, height=0)])  # mempool after confirmed
        bad(entries=[entry(1, 5, height=4), entry(2, -1, height=10)])  # oldest first
        bad(entries=[entry(1, 5, height=11)])  # above the tip
        bad(entries=[entry(1, 5, height=-2)])
        bad(entries=[entry(1, 5, height=4), entry(1, 5, height=3)])  # twice
        bad(entries=[entry(1, 5, {'': 3}, height=4)])
        bad(entries=[entry(1, 5, {'A': 1.5}, height=4)])
        bad(entries=[dict(entry(1, 5, height=4), value='5')])
        bad(complete=1)
        bad(total=2)  # fewer than the entries
        with self.assertRaises(RequestCorrupted):
            _assert_recent_history(good, offset=0, limit=2)
        # beyond the end: no entries (e.g. the mempool lost one between two pages)
        _assert_recent_history(dict(good, entries=[]), offset=5, limit=50)
        with self.assertRaises(RequestCorrupted):
            _assert_recent_history(good, offset=1, limit=50)


class FakeNetwork:
    def __init__(self, chain):
        self.chain = chain

    def blockchain(self):
        return self

    def get_hash(self, height):
        return self.chain[height]


ADDR = 'NbiD2ZWQx79GETVRmxxPXUD8T9wMXfLhzo'
ADDR2 = 'NihAfZynHrTtYPH8ZSUEhLSCVMstLSV5qN'


class TestSynchronizerRecentHistory(ElectrumTestCase):
    """Synchronizer._sync_recent_history, with a fake server and wallet."""

    def make_synchronizer(self, server):
        sync = Synchronizer.__new__(Synchronizer)
        sync.logger = get_logger('test')
        sync.interface = server
        sync.network = FakeNetwork({h: block_hash(h) for h in range(1, 200)})
        sync._network_request_semaphore = asyncio.Semaphore(4)
        sync._requests_sent = sync._requests_answered = 0
        sync._recent_history_unavailable = set()
        sync.adb = mock.Mock()
        return sync

    async def test_stored_with_status_and_counted(self):
        server = FakeServer()
        for n in range(1, 61):
            server.add_block([entry(n, n)])
        sync = self.make_synchronizer(server)
        await sync._sync_recent_history(ADDR, 'status1', None)
        recent = sync.adb.receive_recent_history_callback.call_args[0][1]
        self.assertEqual('status1', recent['status'])
        self.assertEqual(60, len(recent['entries']))
        self.assertEqual((2, 2), (sync._requests_sent, sync._requests_answered))

    async def test_utxo_status_brings_it(self):
        server = FakeServer()
        server.add_block([entry(1, 5)])
        sync = self.make_synchronizer(server)
        sync._handling_utxo_statuses = {ADDR}
        sync.requested_utxo_sets = set()
        sync.requested_recent_histories = set()
        # the UTXO set is up to date (e.g. kept from before the server had it): only the recent history is asked for
        sync.adb.db.get_utxo_set.return_value = {'status': 's1'}
        sync.adb.db.get_recent_history.return_value = None
        await sync._on_utxo_status(ADDR, 's1')
        recent = sync.adb.receive_recent_history_callback.call_args[0][1]
        self.assertEqual(('s1', 1), (recent['status'], len(recent['entries'])))
        self.assertEqual((set(), set()), (sync._handling_utxo_statuses, sync.requested_recent_histories))
        # both up to date: nothing asked for
        sync.adb.reset_mock()
        sync.adb.db.get_utxo_set.return_value = {'status': 's1'}
        sync.adb.db.get_recent_history.return_value = recent
        await sync._on_utxo_status(ADDR, 's1')
        sync.adb.receive_recent_history_callback.assert_not_called()
        self.assertEqual(1, len(server.calls))

    async def test_servers_without_it(self):
        server = FakeServer()
        sync = self.make_synchronizer(server)
        stored = {'height': 1, 'block_hash': block_hash(1), 'complete': True, 'entries': [], 'status': 'old'}
        # an old server: what we keep of another one is dropped once out of date
        server.supports_recent_history = mock.AsyncMock(return_value=False)
        await sync._sync_recent_history(ADDR, 'new', stored)
        sync.adb.receive_recent_history_callback.assert_called_once_with(ADDR, None)
        self.assertEqual(0, sync._requests_sent)
        # an address the server has no recent history of: asked once per connection
        server.supports_recent_history = mock.AsyncMock(return_value=True)
        server.get_recent_history = mock.AsyncMock(side_effect=RPCError(RECENT_HISTORY_UNAVAILABLE, 'no'))
        sync.adb.reset_mock()
        await sync._sync_recent_history(ADDR, 'new', stored)
        sync.adb.receive_recent_history_callback.assert_called_once_with(ADDR, None)
        await sync._sync_recent_history(ADDR, 'newer', None)
        self.assertEqual(1, server.get_recent_history.call_count)
        # other errors are the server's
        server.get_recent_history = mock.AsyncMock(side_effect=RPCError(1, 'bad request'))
        with self.assertRaises(RPCError):
            await sync._sync_recent_history(ADDR2, 'new', None)


class TestWalletRecentHistory(ElectrumTestCase):
    """The history of a wallet with an address followed by its UTXOs."""

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
        w.db.put('stored_height', 150)
        return w

    @staticmethod
    def utxo_set(utxos, mempool_added=None):
        s = {'block_hash': '11' * 32, 'height': 150, 'set_hash': to_hex(utxo_sync.set_hash(utxos)),
             'utxos': utxos, 'mempool_added': mempool_added or {}, 'mempool_spent': []}
        s['status'] = utxo_sync.status(s)
        return s

    def setup_miner(self, w, *, complete=False):
        """A big address with 1000 XNA and 5 TOKEN, and its last entries."""
        address = w.get_receiving_addresses()[0]
        utxos = {txid(1) + ':0': [149, 600_00000000, None, True],
                 txid(2) + ':0': [140, 400_00000000, None, False],
                 txid(3) + ':1': [140, 5, 'TOKEN', False]}
        w.adb.receive_utxo_set_callback(address, self.utxo_set(utxos, {txid(9) + ':0': [7_00000000, None]}))
        entries = [
            [txid(9), 0, 7_00000000, []],
            [txid(1), 149, 600_00000000, []],
            [txid(4), 145, -100_00000000, [['TOKEN', -2]]],
            [txid(2), 140, 400_00000000, []],
            [txid(3), 140, 0, [['TOKEN', 7]]],
        ]
        recent = {'height': 150, 'block_hash': '11' * 32, 'complete': complete, 'entries': entries, 'status': 's'}
        w.adb.receive_recent_history_callback(address, recent)
        return address

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_history_of_the_entries(self, mock_save_db):
        w = self.create_wallet()
        address = self.setup_miner(w)
        # the other users of the history don't see them
        self.assertEqual([], list(w.get_full_history().values()))
        self.assertEqual([], list(w.get_detailed_history()['transactions']))

        h = w.get_full_history(include_recent=True)
        rows = [(k, v['bc_value'].value, v['balance'].value, v['height'], v.get('recent')) for k, v in h.items()]
        self.assertEqual([
            ((txid(2), None), 400_00000000, 500_00000000, 140, True),
            ((txid(3), 'TOKEN'), 7, 7, 140, True),  # no XNA row: it moves an asset only
            ((txid(4), None), -100_00000000, 400_00000000, 145, True),
            ((txid(4), 'TOKEN'), -2, 5, 145, True),
            ((txid(1), None), 600_00000000, 1000_00000000, 149, True),
            ((txid(9), None), 7_00000000, 1007_00000000, 0, True),
        ], rows)
        # the balance ends at the current one, counted from the UTXOs
        self.assertEqual((400_00000000, 7_00000000, 600_00000000), w.get_balance())
        self.assertEqual((5, 0, 0), w.get_balance(asset_aware=True)['TOKEN'])
        item = h[(txid(1), None)]
        self.assertEqual(2, item['confirmations'])
        self.assertIsNone(item['timestamp'])  # no headers: shown by height
        self.assertEqual((5, 'Block 149'), w.get_recent_tx_status(w.adb.recent_tx_mined_info(149)))
        self.assertEqual((9, 'Block 140'), w.get_recent_tx_status(w.adb.recent_tx_mined_info(140)))
        self.assertEqual((0, 'Unconfirmed'), w.get_recent_tx_status(w.adb.recent_tx_mined_info(0)))
        self.assertEqual((1, 'Unconfirmed parent'), w.get_recent_tx_status(w.adb.recent_tx_mined_info(-1)))
        self.assertEqual([(address, 5)], w.get_incomplete_recent_histories())
        # the latest ones only (e.g. for the overview), newest last
        latest = w.adb.get_history_with_recent(w.get_addresses(), limit=2)
        self.assertEqual([txid(1), txid(9)], [i.txid for i in latest])
        self.assertEqual(1007_00000000, latest[-1].balance)
        # a complete history has no notice; without the UTXO set, nothing is shown
        recent = dict(w.db.get_recent_history(address), complete=True)
        w.adb.receive_recent_history_callback(address, recent)
        self.assertEqual([], w.get_incomplete_recent_histories())
        w.db.utxo_sets.pop(address)
        self.assertEqual([], list(w.get_full_history(include_recent=True)))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_normal_addresses_unchanged(self, mock_save_db):
        w = self.create_wallet()
        address = w.get_receiving_addresses()[1]
        funding = PartialTransaction.from_io(
            [PartialTxInput(prevout=TxOutpoint(txid=bytes(range(32)), out_idx=1))],
            [PartialTxOutput.from_address_and_value(address, 12_345)], locktime=0, version=2)
        funding = Transaction(funding.serialize_to_network(include_sigs=False))
        w.adb.receive_history_callback(address, [(funding.txid(), 120)], {})
        w.adb.receive_tx_callback(funding.txid(), funding, 120)
        self.assertEqual(1, len(w.get_full_history()))
        self.assertEqual(w.get_full_history(), w.get_full_history(include_recent=True))
        # and next to an address with a recent history, they count as before
        self.setup_miner(w)
        h = w.get_full_history(include_recent=True)
        item = h[(funding.txid(), None)]
        self.assertEqual(12_345, item['bc_value'].value)
        self.assertNotIn('recent', item)
        newest = list(h.values())[-1]
        self.assertEqual(sum(w.get_balance()), newest['balance'].value)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_own_transactions(self, mock_save_db):
        w = self.create_wallet()
        address = self.setup_miner(w)
        # a payment from the big address (its change goes to a change address)
        destination = 'NbiD2ZWQx79GETVRmxxPXUD8T9wMXfLhzo'
        outputs = [PartialTxOutput.from_address_and_value(destination, 50_00000000)]
        coins = [c for c in w.get_spendable_coins(None) if c.prevout.to_str() == txid(2) + ':0']
        tx = w.make_unsigned_transaction(coins=coins, outputs=outputs, fee=10_000, rbf=False)
        w.sign_transaction(tx, password=None)
        w.adb.add_transaction(tx)
        sent = tx.txid()
        self.assertEqual(TX_HEIGHT_LOCAL, w.adb.get_tx_height(sent).height)
        h = w.get_full_history(include_recent=True)
        # not known to the server yet: counted from the UTXO set
        item = h[(sent, None)]
        self.assertEqual(-50_00010000, item['bc_value'].value)
        self.assertNotIn('recent', item)
        self.assertEqual(sum(w.get_balance()), item['balance'].value)
        # sent: the server's entry (and the change address's history) from now on
        change = [o for o in tx.outputs() if o.address != destination][0]
        w.adb.receive_history_callback(change.address, [(sent, TX_HEIGHT_UNCONFIRMED)], {})
        recent = w.db.get_recent_history(address)
        entries = [[sent, 0, -400_00000000, []]] + list(recent['entries'])
        w.adb.receive_recent_history_callback(address, dict(recent, entries=entries))
        h = w.get_full_history(include_recent=True)
        item = h[(sent, None)]
        self.assertEqual(-50_00010000, item['bc_value'].value)
        self.assertNotIn('recent', item)  # we have it
        self.assertEqual(0, item['height'])

        # a transaction downloaded to be shown: the server's amount, not to be saved
        funding = PartialTransaction.from_io(
            [PartialTxInput(prevout=TxOutpoint(txid=bytes(range(32)), out_idx=1))],
            [PartialTxOutput.from_address_and_value(address, 600_00000000)], locktime=0, version=2)
        funding = Transaction(funding.serialize_to_network(include_sigs=False))
        recent = w.db.get_recent_history(address)
        entries = [[funding.txid(), 149, 600_00000000, []]] + list(recent['entries'])
        w.adb.receive_recent_history_callback(address, dict(recent, entries=entries))
        info = w.get_tx_info(funding)
        self.assertEqual(600_00000000, info.amount)
        self.assertFalse(info.can_save_as_local)
        self.assertFalse(info.can_broadcast)
        self.assertEqual('2 confirmations', info.status)
