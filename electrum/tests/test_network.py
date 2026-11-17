import asyncio
import os
import tempfile
import unittest

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface, ServerAddr, RequestCorrupted
from electrum.crypto import sha256
from electrum import util

from . import ElectrumTestCase
from .test_blockchain import NeuraiUnitTestNet, NeuraiUnitTestNetSha256d, make_header_tree


class MockTaskGroup:
    async def spawn(self, x): return

class MockNetwork:
    taskgroup = MockTaskGroup()

    def __init__(self):
        self.asyncio_loop = util.get_asyncio_loop()

class MockSession:
    """Serves blockchain.block.headers from a dict: height -> header hex."""
    def __init__(self, headers_hex):
        self.headers_hex = headers_hex
    async def send_request(self, method, params):
        assert method == 'blockchain.block.headers', method
        height, count = params
        hexes = [self.headers_hex[h] for h in range(height, height + count) if h in self.headers_hex]
        return {'count': len(hexes), 'hex': ''.join(hexes), 'max': 2016}

class MockInterface(Interface):
    def __init__(self, config):
        self.config = config
        network = MockNetwork()
        network.config = config
        super().__init__(network=network, server=ServerAddr.from_str('mock-server:50000:t'), proxy=None)
        self.q = asyncio.Queue()
        self.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0,
                                                parent=None, forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        self.tip = 12
        self.blockchain._size = self.tip + 1
    async def get_block_header(self, height, assert_mode):
        assert self.q.qsize() > 0, (height, assert_mode)
        item = await self.q.get()
        print("step with height", height, item)
        assert item['block_height'] == height, (item['block_height'], height)
        assert assert_mode in item['mock'], (assert_mode, item)
        return item

class TestNetwork(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.net = NeuraiUnitTestNet

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.interface = MockInterface(self.config)

    async def test_fork_noconflict(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=7)
        self.assertEqual(('fork', 8), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    async def test_fork_conflict(self):
        blockchain.blockchains = {7: {'check': lambda bad_header: False}}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=7)
        self.assertEqual(('fork', 8), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    async def test_can_connect_during_backward(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 2
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=4)
        self.assertEqual(('catchup', 5), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    def mock_fork(self, bad_header):
        forkpoint = bad_header['block_height']
        b = blockchain.Blockchain(config=self.config, forkpoint=forkpoint, parent=None,
                                  forkpoint_hash=sha256(str(forkpoint)).hex(), prev_hash=sha256(str(forkpoint-1)).hex())
        return b

    async def test_chain_false_during_binary(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        mock_connect = lambda height: height == 3
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: False, 'fork': self.mock_fork, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=6)
        self.assertEqual(('catchup', 7), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    async def test_request_chunk_with_legacy_genesis(self):
        # Neurai servers send the pre-KAWPOW genesis as an 80-byte header and
        # the following blocks as 120-byte KAWPOW headers in the same chunk.
        raw_headers, _ = make_header_tree((('A', None), ('B', 'A'), ('C', 'B'), ('D', 'C'), ('E', 'D'), ('F', 'E')))
        served = {height: raw_headers[label].hex() for height, label in enumerate('ABCDEF')}
        blockchain.blockchains = {}
        ifa = self.interface
        ifa.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0, parent=None,
                                               forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(ifa.blockchain.path(), 'w+').close()
        ifa.session = MockSession(served)
        self.assertEqual((True, 6), await ifa.request_chunk(0, tip=5))
        self.assertEqual(5, ifa.blockchain.height())
        # a genesis padded to 120 bytes does not fit the expected chunk size
        served[0] = served[0].ljust(240, '0')
        with self.assertRaises(RequestCorrupted):
            await ifa.request_chunk(0, tip=5)


class TestNetworkSha256d(ElectrumTestCase):
    """Header chunks of a network with the headers of the testnet."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.net = NeuraiUnitTestNetSha256d

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.interface = MockInterface(self.config)

    async def test_request_chunk_with_sha256d_headers(self):
        # testnet servers send every header as 80 bytes; they are stored as 80-byte records
        labels = 'ABCDEF'
        raw_headers, headers = make_header_tree(tuple(zip(labels, (None,) + tuple(labels[:-1]))),
                                                NeuraiUnitTestNetSha256d)
        served = {height: raw_headers[label].hex() for height, label in enumerate(labels)}
        blockchain.blockchains = {}
        ifa = self.interface
        ifa.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0, parent=None,
                                               forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(ifa.blockchain.path(), 'w+').close()
        ifa.session = MockSession(served)
        self.assertEqual((True, 6), await ifa.request_chunk(0, tip=5))
        self.assertEqual(5, ifa.blockchain.height())
        self.assertEqual(6 * 80, os.stat(ifa.blockchain.path()).st_size)
        for height, label in enumerate(labels):
            self.assertEqual(headers[label], ifa.blockchain.read_header(height))
        # a header padded to 120 bytes (the size of KAWPOW headers) does not fit
        served[3] = served[3].ljust(240, '0')
        with self.assertRaises(RequestCorrupted):
            await ifa.request_chunk(0, tip=5)


if __name__=="__main__":
    constants.net = NeuraiUnitTestNet
    unittest.main()
