"""The DePIN-Test testnet: SHA256d 80-byte headers, checkpoints and constants."""
import json
import os
import struct

from electrum import bitcoin, blockchain, constants
from electrum.blockchain import (Blockchain, deserialize_header, serialize_header, hash_header,
                                 header_size, sha256d_headers)
from electrum.crypto import sha256d
from electrum.simple_config import SimpleConfig
from electrum.interface import RequestCorrupted
from electrum.util import bfh

from . import ElectrumTestCase
from .test_network import MockInterface, MockSession


# Real testnet headers, from the node (see the description in the file).
with open(os.path.join(os.path.dirname(__file__), 'blockchain_testnet_headers.json')) as f:
    FIXTURE = json.load(f)
CHUNK_FIRST_HEIGHT = FIXTURE['chunk']['first_height']
CHUNK_HEADERS = [bfh(x) for x in FIXTURE['chunk']['headers']]
CHUNK_HASHES = FIXTURE['chunk']['hashes']
# last checkpoint inside FIXTURE['chunk']: the end of checkpoint chunk 15
LAST_CHECKPOINT = 16 * 2016 - 1


def known_hashes() -> dict:
    hashes = {int(height): d['hash'] for height, d in FIXTURE['headers'].items()}
    hashes.update({CHUNK_FIRST_HEIGHT + i: h for i, h in enumerate(CHUNK_HASHES)})
    return hashes


class TestnetUpToChunk15(constants.NeuraiTestnet):
    """The testnet with the checkpoints that the fixture reaches."""
    DGW_CHECKPOINTS = constants.NeuraiTestnet.DGW_CHECKPOINTS[:16]


class TestTestnetConstants(ElectrumTestCase):
    TESTNET = True

    def test_network(self):
        net = constants.net
        self.assertIs(constants.NeuraiTestnet, net)
        self.assertTrue(net.TESTNET)
        self.assertTrue(sha256d_headers())
        self.assertEqual(80, header_size())
        self.assertEqual("000000c710413a4265a996d30c86043aedef6a563900f1bc43fea61d5b2dc77d", net.GENESIS)
        self.assertEqual(1, net.BIP44_COIN_TYPE)
        self.assertEqual(b'xna', net.ASSET_PREFIX)

    def test_addresses(self):
        self.assertTrue(bitcoin.hash160_to_p2pkh(bytes(20)).startswith('t'))
        self.assertEqual(196, bitcoin.b58_address_to_hash160(bitcoin.hash160_to_p2sh(bytes(20)))[0])
        self.assertEqual(239, constants.net.WIF_PREFIX)
        self.assertEqual(0x043587cf, constants.net.XPUB_HEADERS['standard'])
        self.assertEqual(0x04358394, constants.net.XPRV_HEADERS['standard'])
        for burn_address in constants.net.BURN_ADDRESSES:
            with self.subTest(burn_address):
                addrtype, _ = bitcoin.b58_address_to_hash160(burn_address)
                self.assertEqual(constants.net.ADDRTYPE_P2PKH, addrtype)

    def test_mainnet_unchanged(self):
        self.assertTrue(constants.NeuraiTestnet.SHA256D_HEADERS)
        constants.set_mainnet()
        try:
            self.assertFalse(sha256d_headers())
            self.assertEqual(120, header_size())
        finally:
            constants.set_testnet()


class TestTestnetHeaderHashes(ElectrumTestCase):
    TESTNET = True

    def test_genesis_header(self):
        raw = FIXTURE['headers']['0']['hex']
        header = deserialize_header(bfh(raw), 0)
        self.assertEqual({
            'version': 2,
            'prev_block_hash': '00' * 32,
            'merkle_root': '4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951',
            'timestamp': 1793836800,
            'bits': 0x1e00ffff,
            'nonce': 2915850,
            'block_height': 0,
        }, header)
        self.assertEqual(constants.net.GENESIS, hash_header(header))
        self.assertEqual(raw, serialize_header(header))
        Blockchain.verify_header(header, '00' * 32, 0, expected_header_hash=constants.net.GENESIS)

    def test_header_hashes(self):
        # hashes from getblockhash: SHA256d of the 80-byte header, without padding
        headers = {int(height): d['hex'] for height, d in FIXTURE['headers'].items()}
        headers.update({CHUNK_FIRST_HEIGHT + i: x for i, x in enumerate(FIXTURE['chunk']['headers'])})
        hashes = known_hashes()
        for height, raw in sorted(headers.items()):
            with self.subTest(height=height):
                self.assertEqual(160, len(raw))
                header = deserialize_header(bfh(raw), height)
                self.assertNotIn('mix_hash', header)
                self.assertEqual(hashes[height], hash_header(header))
                self.assertEqual(raw, serialize_header(header))
                if height - 1 in hashes:
                    self.assertEqual(hashes[height - 1], header['prev_block_hash'])
                    Blockchain.verify_header(header, hashes[height - 1], 0, expected_header_hash=hashes[height])

    def test_kawpow_sized_header_is_invalid(self):
        raw = bfh(FIXTURE['headers']['1']['hex'])
        with self.assertRaises(blockchain.InvalidHeader):
            deserialize_header(raw + bytes(40), 1)


class TestTestnetCheckpoints(ElectrumTestCase):
    TESTNET = True

    def test_checkpoints(self):
        net = constants.net
        cps = net.DGW_CHECKPOINTS
        self.assertGreaterEqual(len(cps), 16)
        self.assertEqual(len(cps) * 2016 - 1, net.max_checkpoint())
        self.assertEqual(net.GENESIS, cps[0][0][0])
        chain = Blockchain(config=SimpleConfig({'electrum_path': self.electrum_path}),
                           forkpoint=0, parent=None, forkpoint_hash=net.GENESIS, prev_hash=None)
        checked = 0
        for height, header_hash in known_hashes().items():
            if height <= net.max_checkpoint() and Blockchain.is_dgw_height_checkpoint(height) is not None:
                self.assertEqual(header_hash, chain.get_hash(height))
                checked += 1
        self.assertGreaterEqual(checked, 4)  # 0, 2015, 2016 and 32255 at least
        # targets of the checkpoints: from the bits of their headers
        for height, (cp_hash, target) in ((0, cps[0][0]), (2015, cps[0][1]), (2016, cps[1][0])):
            header = deserialize_header(bfh(FIXTURE['headers'][str(height)]['hex']), height)
            self.assertEqual(Blockchain.bits_to_target(header['bits']), target)


class TestTestnetHeadersFile(ElectrumTestCase):
    """Startup: headers past the last checkpoint, saved as 80-byte records."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.net = TestnetUpToChunk15

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        blockchain.blockchains = {}

    def load_chains(self) -> Blockchain:
        blockchain.read_blockchains(self.config)
        blockchain.init_headers_file_for_best_chain()
        return blockchain.get_best_chain()

    async def test_connect_chunk_after_checkpoints(self):
        self.assertEqual(LAST_CHECKPOINT, constants.net.max_checkpoint())
        chain = self.load_chains()
        # a sparse file with a record for every header in the checkpoint region
        self.assertEqual(80 * (LAST_CHECKPOINT + 1), os.stat(chain.path()).st_size)
        self.assertEqual(LAST_CHECKPOINT, chain.height())
        self.assertIsNone(chain.read_header(LAST_CHECKPOINT))
        self.assertEqual(known_hashes()[LAST_CHECKPOINT], chain.get_hash(LAST_CHECKPOINT))

        start = LAST_CHECKPOINT + 1 - CHUNK_FIRST_HEIGHT
        after_cp = CHUNK_HEADERS[start:]
        self.assertTrue(chain.can_connect(deserialize_header(after_cp[0], LAST_CHECKPOINT + 1)))
        self.assertTrue(await chain.connect_chunk(LAST_CHECKPOINT + 1, b''.join(after_cp).hex()))
        tip = LAST_CHECKPOINT + len(after_cp)
        self.assertEqual(tip, chain.height())
        self.assertEqual(80 * (tip + 1), os.stat(chain.path()).st_size)
        for i, raw in enumerate(after_cp):
            height = LAST_CHECKPOINT + 1 + i
            self.assertEqual(deserialize_header(raw, height), chain.read_header(height))
            self.assertEqual(CHUNK_HASHES[start + i], chain.get_hash(height))

        # the headers file is read back after a restart
        blockchain.blockchains = {}
        chain = self.load_chains()
        self.assertEqual(tip, chain.height())
        self.assertEqual(CHUNK_HASHES[-1], chain.get_hash(tip))

    async def test_bad_chunks_after_checkpoints(self):
        chain = self.load_chains()
        start = LAST_CHECKPOINT + 1 - CHUNK_FIRST_HEIGHT
        after_cp = CHUNK_HEADERS[start:]
        # another merkle root breaks the link to the next header
        tampered = list(after_cp)
        tampered[3] = tampered[3][:36] + bytes(32) + tampered[3][68:]
        self.assertFalse(await chain.connect_chunk(LAST_CHECKPOINT + 1, b''.join(tampered).hex()))
        # a gap after the last checkpoint
        self.assertFalse(await chain.connect_chunk(LAST_CHECKPOINT + 2, b''.join(after_cp[1:]).hex()))
        # 120-byte (KAWPOW-sized) headers
        padded = b''.join(raw + bytes(40) for raw in after_cp)
        self.assertFalse(await chain.connect_chunk(LAST_CHECKPOINT + 1, padded.hex()))
        # headers before the last checkpoint do not start a chunk after it
        self.assertFalse(await chain.connect_chunk(LAST_CHECKPOINT + 1, b''.join(CHUNK_HEADERS).hex()))
        self.assertEqual(LAST_CHECKPOINT, chain.height())
        self.assertEqual(80 * (LAST_CHECKPOINT + 1), os.stat(chain.path()).st_size)

    def test_headers_file_of_another_format(self):
        # a headers file of the previous testnet (other genesis, 120-byte records)
        # that reaches past the checkpoints does not connect, and is replaced
        path = os.path.join(self.electrum_path, 'blockchain_headers')
        with open(path, 'wb') as f:
            f.write(bytes(range(120)) * (LAST_CHECKPOINT + 100))
        chain = self.load_chains()
        self.assertEqual(LAST_CHECKPOINT, chain.height())
        self.assertEqual(80 * (LAST_CHECKPOINT + 1), os.stat(path).st_size)
        self.assertIsNone(chain.read_header(LAST_CHECKPOINT - 1))


def make_sha256d_chain(count: int):
    """Synthetic chain of 80-byte headers. Returns (raw headers, hashes)."""
    raws, hashes = [], []
    prev = bytes(32)
    for height in range(count):
        raw = struct.pack('<i32s32sIII', 0x30000000, prev, sha256d(b'merkle %d' % height),
                          1793836800 + 30 * height, 0x2100ffff, height)
        prev = sha256d(raw)
        raws.append(raw)
        hashes.append(prev[::-1].hex())
    return raws, hashes


class TestSha256dCheckpointChunks(ElectrumTestCase):
    """Chunks of 80-byte headers in the checkpoint region, as the client
    fetches them on demand (SPV of a transaction below the last checkpoint)."""

    RAWS, HASHES = make_sha256d_chain(2 * 2016 + 10)

    class Net(constants.NeuraiTestnet):
        pass

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        target = Blockchain.bits_to_target(0x2100ffff)
        cls.Net.GENESIS = cls.HASHES[0]
        cls.Net.DGW_CHECKPOINTS = [[[cls.HASHES[k * 2016], target], [cls.HASHES[k * 2016 + 2015], target]]
                                   for k in range(2)]
        constants.net = cls.Net

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        blockchain.blockchains = {}
        blockchain.read_blockchains(self.config)
        blockchain.init_headers_file_for_best_chain()
        self.chain = blockchain.get_best_chain()

    def chunk(self, start: int, end: int) -> str:
        return b''.join(self.RAWS[start:end]).hex()

    async def test_chunks_in_checkpoint_region(self):
        chain = self.chain
        self.assertEqual(4031, constants.net.max_checkpoint())
        self.assertEqual(80 * 4032, os.stat(chain.path()).st_size)
        # the second chunk, alone
        self.assertTrue(await chain.connect_chunk(2016, self.chunk(2016, 4032)))
        self.assertIsNone(chain.read_header(2015))
        for height in (2016, 3000, 4031):
            self.assertEqual(deserialize_header(self.RAWS[height], height), chain.read_header(height))
            self.assertEqual(self.HASHES[height], chain.get_hash(height))
        # then the first one, and the headers after the checkpoints
        self.assertTrue(await chain.connect_chunk(0, self.chunk(0, 2016)))
        self.assertEqual(deserialize_header(self.RAWS[0], 0), chain.read_header(0))
        self.assertTrue(await chain.connect_chunk(4032, self.chunk(4032, 4042)))
        self.assertEqual(4041, chain.height())
        self.assertEqual(80 * 4042, os.stat(chain.path()).st_size)
        self.assertEqual(self.HASHES[4041], chain.get_hash(4041))

    async def test_bad_chunks_in_checkpoint_region(self):
        chain = self.chain
        # another header in the middle of the chunk
        raws = list(self.RAWS[2016:4032])
        raws[100] = raws[100][:76] + b'\xff\xff\xff\xff'
        self.assertFalse(await chain.connect_chunk(2016, b''.join(raws).hex()))
        # another last header: its hash is not the checkpoint
        raws = list(self.RAWS[2016:4032])
        raws[-1] = raws[-1][:76] + b'\xff\xff\xff\xff'
        self.assertFalse(await chain.connect_chunk(2016, b''.join(raws).hex()))
        # not a full chunk
        self.assertFalse(await chain.connect_chunk(2016, self.chunk(2016, 4031)))
        for height in (2016, 2116, 4031):
            self.assertIsNone(chain.read_header(height))

    async def test_request_chunk_in_checkpoint_region(self):
        # what SPV does for a transaction at height 2100
        served = {height: raw.hex() for height, raw in enumerate(self.RAWS)}
        ifa = MockInterface(self.config)
        ifa.blockchain = self.chain
        ifa.session = MockSession(served)
        self.assertEqual((True, 2016), await ifa.request_chunk(2100, None))
        self.assertEqual(deserialize_header(self.RAWS[2100], 2100), self.chain.read_header(2100))
        # a server that pads the headers to 120 bytes
        served = {height: raw.hex().ljust(240, '0') for height, raw in enumerate(self.RAWS)}
        ifa.session = MockSession(served)
        with self.assertRaises(RequestCorrupted):
            await ifa.request_chunk(0, None)
        self.assertIsNone(self.chain.read_header(0))
