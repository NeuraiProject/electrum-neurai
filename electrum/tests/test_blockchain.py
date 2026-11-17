import json
import shutil
import tempfile
import os
import struct

from electrum import constants, blockchain
from electrum.crypto import sha256d
from electrum.simple_config import SimpleConfig
from electrum.blockchain import (Blockchain, deserialize_header, hash_header, InvalidHeader,
                                 HEADER_SIZE, DGW_PASTBLOCKS)
from electrum.util import bfh, make_dir

from . import ElectrumTestCase


class NeuraiUnitTestNet(constants.NeuraiTestnet):
    """Regtest-like network for unit tests.

    Its genesis is header 'A' of TestBlockchain.HEADERS and it has no
    checkpoints, so forks can start at any height. Like any TESTNET,
    bits and proof of work are not checked and chainwork == height.
    """
    NET_NAME = "regtest"
    GENESIS = "5d5c7ac641d18951ceae27616156b7acc4178d077c81c816ea2e784b47c99817"
    CHECKPOINTS = []
    DGW_CHECKPOINTS = []


def make_raw_header(label: str, height: int, prev_hash: str) -> bytes:
    """Deterministic synthetic header for block `label` at `height`, child of `prev_hash`.

    As on Neurai, the genesis (height 0) is a legacy 80-byte header hashed
    with X16R (timestamp just before KawpowActivationTS), and every other
    block is a 120-byte KAWPOW header with nheight, a 64-bit nonce and
    mix_hash. The merkle root and mix_hash are derived from the label, so
    blocks at the same height on different branches get different hashes.
    nonce/mix_hash are not real PoW solutions: kawpow.light_verify hashes
    any value, and PoW is not checked on test networks.
    """
    version, bits = 0x20000000, 0x207fffff
    genesis_time = NeuraiUnitTestNet.KawpowActivationTS - 1
    merkle_root = sha256d(b'merkle ' + label.encode())
    if height == 0:
        return struct.pack('<i32s32sIII', 4, bytes(32), merkle_root, genesis_time, bits, 0)
    mix_hash = sha256d(b'mix ' + label.encode())
    return struct.pack('<i32s32sIIIQ32s', version, bfh(prev_hash)[::-1], merkle_root,
                       genesis_time + 60 * height, bits, height, height, mix_hash)


def make_header_tree(tree):
    """tree: sequence of (label, parent label or None), parents first.
    Returns (raw headers, deserialized headers), both keyed by label."""
    raw_headers, headers = {}, {}
    for label, parent in tree:
        height = headers[parent]['block_height'] + 1 if parent else 0
        prev_hash = hash_header(headers[parent]) if parent else '00' * 32
        raw_headers[label] = make_raw_header(label, height, prev_hash)
        headers[label] = deserialize_header(raw_headers[label], height)
    return raw_headers, headers


class TestBlockchain(ElectrumTestCase):

    # tree of headers:
    #                                            - M <- N <- X <- Y <- Z
    #                                          /
    #                             - G <- H <- I <- J <- K <- L
    #                           /
    # A <- B <- C <- D <- E <- F <- O <- P <- Q <- R <- S <- T <- U
    RAW_HEADERS, HEADERS = make_header_tree((
        ('A', None), ('B', 'A'), ('C', 'B'), ('D', 'C'), ('E', 'D'), ('F', 'E'),
        ('O', 'F'), ('P', 'O'), ('Q', 'P'), ('R', 'Q'), ('S', 'R'), ('T', 'S'), ('U', 'T'),
        ('G', 'F'), ('H', 'G'), ('I', 'H'), ('J', 'I'), ('K', 'J'), ('L', 'K'),
        ('M', 'I'), ('N', 'M'), ('X', 'N'), ('Y', 'X'), ('Z', 'Y'),
    ))

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.net = NeuraiUnitTestNet

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        super().setUp()
        self.data_dir = self.electrum_path
        make_dir(os.path.join(self.data_dir, 'forks'))
        self.config = SimpleConfig({'electrum_path': self.data_dir})
        blockchain.blockchains = {}

    def _append_header(self, chain: Blockchain, header: dict):
        self.assertTrue(chain.can_connect(header))
        chain.save_header(header)

    def test_get_height_of_last_common_block_with_chain(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual({chain_u:  8, chain_l: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11},             chain_l.get_parent_heights())

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual({chain_u:  8, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual({chain_u: 12, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

    def test_parents_after_forking(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        self.assertEqual(None, chain_u.parent)

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual(None,    chain_l.parent)
        self.assertEqual(chain_l, chain_u.parent)

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

    def test_forking_and_swapping(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])

        # do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_u.forkpoint)
        self.assertEqual(None, chain_u.parent)
        self.assertEqual(constants.net.GENESIS, chain_u._forkpoint_hash)
        self.assertEqual(None, chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_u.path())
        self.assertEqual(10 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        self.assertEqual(6, chain_l.forkpoint)
        self.assertEqual(chain_u, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['G']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_26565462a36030638b8b81173b51641677983ceac4eba169933c0c73b64e3f8c_b4b26dcd7e8cc4e40621e78d06f5602ed17c785d87a87fd16e836d45fef988d0"), chain_l.path())
        self.assertEqual(4 * HEADER_SIZE, os.stat(chain_l.path()).st_size)

        self._append_header(chain_l, self.HEADERS['K'])

        # chains were swapped, do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_l, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_26565462a36030638b8b81173b51641677983ceac4eba169933c0c73b64e3f8c_e1efb7906e3753febe47b1854c0bf762ae3e4c49f0e936f58e0da46a821c4941"), chain_u.path())
        self.assertEqual(4 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        self.assertEqual(0, chain_l.forkpoint)
        self.assertEqual(None, chain_l.parent)
        self.assertEqual(constants.net.GENESIS, chain_l._forkpoint_hash)
        self.assertEqual(None, chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_l.path())
        self.assertEqual(11 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        for b in (chain_u, chain_l):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])
        self._append_header(chain_l, self.HEADERS['L'])

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        # chain_z became best chain, do checks
        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(14 * HEADER_SIZE, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_9_5fd0f0e466d5c91235d99b86299e55342c05f894aa9e55e9566f358097f40207_cb89ad503493e36a9b7b860cddc988335b1e4120f7e1a19078e36a4fc28c1f11"), chain_l.path())
        self.assertEqual(3 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_26565462a36030638b8b81173b51641677983ceac4eba169933c0c73b64e3f8c_e1efb7906e3753febe47b1854c0bf762ae3e4c49f0e936f58e0da46a821c4941"), chain_u.path())
        self.assertEqual(7 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['Z']), chain_z.get_hash(13))

    def test_doing_multiple_swaps_after_single_new_header(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])

        self.assertEqual(1, len(blockchain.blockchains))
        self.assertEqual(0, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        # now chain_u is best chain, but it's tied with chain_l

        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])

        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        # chain_z became best chain, do checks
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(12 * HEADER_SIZE, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_9_5fd0f0e466d5c91235d99b86299e55342c05f894aa9e55e9566f358097f40207_cb89ad503493e36a9b7b860cddc988335b1e4120f7e1a19078e36a4fc28c1f11"), chain_l.path())
        self.assertEqual(2 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", "fork2_6_26565462a36030638b8b81173b51641677983ceac4eba169933c0c73b64e3f8c_e1efb7906e3753febe47b1854c0bf762ae3e4c49f0e936f58e0da46a821c4941"), chain_u.path())
        self.assertEqual(5 * HEADER_SIZE, os.stat(chain_u.path()).st_size)

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['X']), chain_z.get_hash(11))

        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

    def get_chains_that_contain_header_helper(self, header: dict):
        height = header['block_height']
        header_hash = hash_header(header)
        return blockchain.get_chains_that_contain_header(height, header_hash)

    def test_get_chains_that_contain_header(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        chain_z = chain_l.fork(self.HEADERS['M'])

        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['A']))
        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['C']))
        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['F']))
        self.assertEqual([chain_l, chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['G']))
        self.assertEqual([chain_l, chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['I']))
        self.assertEqual([chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['M']))
        self.assertEqual([chain_l], self.get_chains_that_contain_header_helper(self.HEADERS['K']))

        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['A']))
        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['C']))
        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['F']))
        self.assertEqual([chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['O']))
        self.assertEqual([chain_z, chain_l], self.get_chains_that_contain_header_helper(self.HEADERS['I']))

    async def test_connect_chunk_with_legacy_genesis(self):
        # Servers send headers below KawpowActivationHeight (only the genesis)
        # as 80 bytes and the rest as 120-byte KAWPOW headers; on disk every
        # header takes HEADER_SIZE bytes.
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        # C is missing, so D does not connect
        bad_chunk = b''.join(self.RAW_HEADERS[x] for x in 'ABD')
        self.assertFalse(await chain_u.connect_chunk(0, bad_chunk.hex()))
        self.assertEqual(-1, chain_u.height())

        labels = 'ABCDEFOPQ'
        chunk = b''.join(self.RAW_HEADERS[x] for x in labels)
        self.assertEqual(80 + 8 * 120, len(chunk))
        self.assertTrue(await chain_u.connect_chunk(0, chunk.hex()))
        self.assertEqual(8, chain_u.height())
        self.assertEqual(9 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        for height, label in enumerate(labels):
            self.assertEqual(self.HEADERS[label], chain_u.read_header(height))
            self.assertEqual(hash_header(self.HEADERS[label]), chain_u.get_hash(height))
        self.assertTrue(all([chain_u.can_connect(chain_u.read_header(i), False) for i in range(chain_u.height())]))

        # the chain keeps growing and forking header by header
        self._append_header(chain_u, self.HEADERS['R'])
        chain_l = chain_u.fork(self.HEADERS['G'])
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)

    def test_target_to_bits(self):
        # https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.h#L269
        self.assertEqual(0x05123456, Blockchain.target_to_bits(0x1234560000))
        self.assertEqual(0x0600c0de, Blockchain.target_to_bits(0xc0de000000))

        # tests from https://github.com/bitcoin/bitcoin/blob/a7d17daa5cd8bf6398d5f8d7e77290009407d6ea/src/test/arith_uint256_tests.cpp#L411
        tuples = (
            (0, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x00123456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01003456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x02000056, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x03000000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x04000000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x00923456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01803456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x02800056, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x03800000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x04800000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01123456, 0x0000000000000000000000000000000000000000000000000000000000000012, 0x01120000),
            (0x02123456, 0x0000000000000000000000000000000000000000000000000000000000001234, 0x02123400),
            (0x03123456, 0x0000000000000000000000000000000000000000000000000000000000123456, 0x03123456),
            (0x04123456, 0x0000000000000000000000000000000000000000000000000000000012345600, 0x04123456),
            (0x05009234, 0x0000000000000000000000000000000000000000000000000000000092340000, 0x05009234),
            (0x20123456, 0x1234560000000000000000000000000000000000000000000000000000000000, 0x20123456),
        )
        for nbits1, target, nbits2 in tuples:
            with self.subTest(original_compact_nbits=nbits1.to_bytes(length=4, byteorder="big").hex()):
                num = Blockchain.bits_to_target(nbits1)
                self.assertEqual(target, num)
                self.assertEqual(nbits2, Blockchain.target_to_bits(num))

        # Make sure that we don't generate compacts with the 0x00800000 bit set
        self.assertEqual(0x02008000, Blockchain.target_to_bits(0x80))

        with self.assertRaises(InvalidHeader):  # target cannot be negative
            Blockchain.bits_to_target(0x01fedcba)
        with self.assertRaises(InvalidHeader):  # target cannot be negative
            Blockchain.bits_to_target(0x04923456)
        with self.assertRaises(InvalidHeader):  # overflow
            Blockchain.bits_to_target(0xff123456)


class TestVerifyHeader(ElectrumTestCase):

    # Data for Neurai mainnet block header #1000000 (KAWPOW),
    # from neurai-cli getblockheader <hash> false
    valid_header = "0000003023cd5588b1a1c7bd6e6a2c057f766157cd6484779d8bc6e2759703000000000038ff34aadc3af79aa8727b18a020dc5b17e93b447551b59208d3078403f5f2fb42ebd76795380e1b40420f006f3dc3a35a70e0bb377d100892307431c20d61857a04fa154efd9b446def74af6a8f69046ed3eb97"
    block_hash = "000000000002370f2552985148f4231c5af71aa13d975a0205d6bc2df8d6cfbc"
    target = Blockchain.bits_to_target(0x1b0e3895)
    prev_hash = "0000000000039775e2c68b9d778464cd5761767f052c6a6ebdc7a1b18855cd23"

    def setUp(self):
        super().setUp()
        self.header = deserialize_header(bfh(self.valid_header), 1000000)

    def test_valid_header(self):
        self.assertEqual(self.block_hash, hash_header(self.header))
        Blockchain.verify_header(self.header, self.prev_hash, self.target,
                                 expected_header_hash=self.block_hash)

    def test_valid_genesis_header(self):
        # the genesis predates KAWPOW: legacy 80-byte header hashed with X16R
        genesis = deserialize_header(bfh("04000000000000000000000000000000000000000000000000000000000000000000000051595fe1fb519173c0bd75904e460872585a1d38579788d183cd60d993bf284b08063d64ffff001e92cf6c00"), 0)
        self.assertEqual(constants.net.GENESIS, hash_header(genesis))
        Blockchain.verify_header(genesis, '00' * 32, Blockchain.bits_to_target(0x1e00ffff))

    def test_expected_hash_mismatch(self):
        with self.assertRaises(InvalidHeader):
            Blockchain.verify_header(self.header, self.prev_hash, self.target,
                                     expected_header_hash="foo")

    def test_prev_hash_mismatch(self):
        with self.assertRaises(InvalidHeader):
            Blockchain.verify_header(self.header, "foo", self.target)

    def test_target_mismatch(self):
        with self.assertRaises(InvalidHeader):
            other_target = Blockchain.bits_to_target(0x1b0eeeee)
            Blockchain.verify_header(self.header, self.prev_hash, other_target)

    def test_insufficient_pow(self):
        with self.assertRaises(InvalidHeader):
            self.header["nonce"] = 42
            Blockchain.verify_header(self.header, self.prev_hash, self.target)

    def test_dark_gravity_wave(self):
        # Real mainnet headers just above the last DGW checkpoint (1870847);
        # past the checkpoints the client computes every target with DGW from
        # the previous DGW_PASTBLOCKS headers and checks bits and PoW against it.
        with open(os.path.join(os.path.dirname(__file__), 'blockchain_mainnet_headers.json')) as f:
            data = json.load(f)
        first = data['first_height']
        headers = {first + i: deserialize_header(bfh(raw), first + i)
                   for i, raw in enumerate(data['headers'])}
        last = max(headers)
        self.assertEqual(1870857, last)
        self.assertEqual("0000000000802b3d79be15f7742766a257a9595fe059b9a08d3cfefe4a0a7700",
                         hash_header(headers[last]))
        chain = Blockchain(config=SimpleConfig({'electrum_path': self.electrum_path}),
                           forkpoint=0, parent=None, forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        for height in range(first + DGW_PASTBLOCKS + 1, last + 1):
            target = chain.get_target_dgwv3(height, headers)
            Blockchain.verify_header(headers[height], hash_header(headers[height - 1]), target)
        # the target depends on the timestamps of the window
        oldest = last - DGW_PASTBLOCKS
        headers[oldest] = dict(headers[oldest], timestamp=headers[oldest]['timestamp'] - 3600)
        target = chain.get_target_dgwv3(last, headers)
        with self.assertRaisesRegex(InvalidHeader, "bits mismatch"):
            Blockchain.verify_header(headers[last], hash_header(headers[last - 1]), target)
