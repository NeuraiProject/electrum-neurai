import hashlib
import json
import shutil
import tempfile
import os
import struct
import threading
from unittest import mock

import kawpow

from electrum import constants, blockchain, kawpow_full
from electrum.crypto import sha256d
from electrum.simple_config import SimpleConfig
from electrum.blockchain import (Blockchain, deserialize_header, hash_header, InvalidHeader,
                                 HEADER_SIZE, LEGACY_HEADER_SIZE, DGW_PASTBLOCKS,
                                 header_size, sha256d_headers)
from electrum.util import bfh, make_dir

from . import ElectrumTestCase


class NeuraiUnitTestNet(constants.NeuraiTestnet):
    """Regtest-like network for unit tests, with the headers of mainnet.

    Its genesis is header 'A' of TestBlockchain.HEADERS and it has no
    checkpoints, so forks can start at any height. Like any TESTNET,
    bits and proof of work are not checked and chainwork == height.
    """
    NET_NAME = "regtest"
    GENESIS = "5d5c7ac641d18951ceae27616156b7acc4178d077c81c816ea2e784b47c99817"
    CHECKPOINTS = []
    DGW_CHECKPOINTS = []
    # mainnet headers: legacy X16R genesis, then 120-byte KAWPOW headers
    KawpowActivationTS = constants.NeuraiMainnet.KawpowActivationTS
    KawpowActivationHeight = constants.NeuraiMainnet.KawpowActivationHeight
    SHA256D_HEADERS = False


class NeuraiUnitTestNetSha256d(NeuraiUnitTestNet):
    """NeuraiUnitTestNet with the headers of the testnet: 80-byte legacy
    headers only, hashed with SHA256d. GENESIS is set below."""
    KawpowActivationTS = constants.NeuraiTestnet.KawpowActivationTS
    KawpowActivationHeight = constants.NeuraiTestnet.KawpowActivationHeight
    SHA256D_HEADERS = True


def make_raw_header(label: str, height: int, prev_hash: str, net=NeuraiUnitTestNet) -> bytes:
    """Deterministic synthetic header for block `label` at `height`, child of `prev_hash`.

    With the headers of mainnet, the genesis (height 0) is a legacy 80-byte
    header hashed with X16R (timestamp just before KawpowActivationTS), and
    every other block is a 120-byte KAWPOW header with nheight, a 64-bit nonce
    and mix_hash. With SHA256D_HEADERS (testnet), every block is a legacy
    80-byte header. The merkle root and mix_hash are derived from the label, so
    blocks at the same height on different branches get different hashes.
    nonce/mix_hash are not real PoW solutions: kawpow.light_verify hashes
    any value, and PoW is not checked on test networks.
    """
    version, bits = 0x20000000, 0x207fffff
    genesis_time = NeuraiUnitTestNet.KawpowActivationTS - 1
    merkle_root = sha256d(b'merkle ' + label.encode())
    if height == 0:
        return struct.pack('<i32s32sIII', 4, bytes(32), merkle_root, genesis_time, bits, 0)
    if net.SHA256D_HEADERS:
        return struct.pack('<i32s32sIII', version, bfh(prev_hash)[::-1], merkle_root,
                           genesis_time + 60 * height, bits, height)
    mix_hash = sha256d(b'mix ' + label.encode())
    return struct.pack('<i32s32sIIIQ32s', version, bfh(prev_hash)[::-1], merkle_root,
                       genesis_time + 60 * height, bits, height, height, mix_hash)


def make_header_tree(tree, net=NeuraiUnitTestNet):
    """tree: sequence of (label, parent label or None), parents first.
    Returns (raw headers, deserialized headers), both keyed by label,
    in the header format of `net`."""
    raw_headers, headers = {}, {}
    old_net, constants.net = constants.net, net
    try:
        for label, parent in tree:
            height = headers[parent]['block_height'] + 1 if parent else 0
            prev_hash = hash_header(headers[parent]) if parent else '00' * 32
            raw_headers[label] = make_raw_header(label, height, prev_hash, net)
            headers[label] = deserialize_header(raw_headers[label], height)
    finally:
        constants.net = old_net
    return raw_headers, headers


def sha256d_hash(raw_header: bytes) -> str:
    """Block hash of an 80-byte header, computed without electrum."""
    return hashlib.sha256(hashlib.sha256(raw_header).digest()).digest()[::-1].hex()


NeuraiUnitTestNetSha256d.GENESIS = sha256d_hash(make_raw_header('A', 0, '00' * 32, NeuraiUnitTestNetSha256d))


class TestBlockchain(ElectrumTestCase):

    # tree of headers:
    #                                            - M <- N <- X <- Y <- Z
    #                                          /
    #                             - G <- H <- I <- J <- K <- L
    #                           /
    # A <- B <- C <- D <- E <- F <- O <- P <- Q <- R <- S <- T <- U
    TREE = (
        ('A', None), ('B', 'A'), ('C', 'B'), ('D', 'C'), ('E', 'D'), ('F', 'E'),
        ('O', 'F'), ('P', 'O'), ('Q', 'P'), ('R', 'Q'), ('S', 'R'), ('T', 'S'), ('U', 'T'),
        ('G', 'F'), ('H', 'G'), ('I', 'H'), ('J', 'I'), ('K', 'J'), ('L', 'K'),
        ('M', 'I'), ('N', 'M'), ('X', 'N'), ('Y', 'X'), ('Z', 'Y'),
    )
    NET = NeuraiUnitTestNet
    RAW_HEADERS, HEADERS = make_header_tree(TREE, NET)
    # block hashes that name fork files (X16R genesis, KAWPOW after it)
    EXPECTED_HASHES = {
        'F': '26565462a36030638b8b81173b51641677983ceac4eba169933c0c73b64e3f8c',
        'G': 'b4b26dcd7e8cc4e40621e78d06f5602ed17c785d87a87fd16e836d45fef988d0',
        'O': 'e1efb7906e3753febe47b1854c0bf762ae3e4c49f0e936f58e0da46a821c4941',
        'I': '5fd0f0e466d5c91235d99b86299e55342c05f894aa9e55e9566f358097f40207',
        'J': 'cb89ad503493e36a9b7b860cddc988335b1e4120f7e1a19078e36a4fc28c1f11',
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.net = cls.NET

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

    def fork_path(self, forkpoint: int, prev_label: str, first_label: str) -> str:
        prev_hash = hash_header(self.HEADERS[prev_label]).lstrip('0')
        first_hash = hash_header(self.HEADERS[first_label]).lstrip('0')
        return os.path.join(self.data_dir, "forks", f"fork2_{forkpoint}_{prev_hash}_{first_hash}")

    def test_header_hashes(self):
        self.assertEqual(constants.net.GENESIS, hash_header(self.HEADERS['A']))
        for label, expected_hash in self.EXPECTED_HASHES.items():
            self.assertEqual(expected_hash, hash_header(self.HEADERS[label]))
        for label, raw in self.RAW_HEADERS.items():
            height = self.HEADERS[label]['block_height']
            # headers of the network's format only: 80 bytes below KawpowActivationHeight
            size = LEGACY_HEADER_SIZE if height < constants.net.KawpowActivationHeight else HEADER_SIZE
            self.assertEqual(size, len(raw))
            # header records: legacy headers zero-padded to header_size()
            self.assertEqual(raw.ljust(header_size(), b'\x00').hex(), blockchain.serialize_header(self.HEADERS[label]))

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
        self.assertEqual(10 * header_size(), os.stat(chain_u.path()).st_size)
        self.assertEqual(6, chain_l.forkpoint)
        self.assertEqual(chain_u, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['G']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)
        self.assertEqual(self.fork_path(6, 'F', 'G'), chain_l.path())
        self.assertEqual(4 * header_size(), os.stat(chain_l.path()).st_size)

        self._append_header(chain_l, self.HEADERS['K'])

        # chains were swapped, do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_l, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(self.fork_path(6, 'F', 'O'), chain_u.path())
        self.assertEqual(4 * header_size(), os.stat(chain_u.path()).st_size)
        self.assertEqual(0, chain_l.forkpoint)
        self.assertEqual(None, chain_l.parent)
        self.assertEqual(constants.net.GENESIS, chain_l._forkpoint_hash)
        self.assertEqual(None, chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_l.path())
        self.assertEqual(11 * header_size(), os.stat(chain_l.path()).st_size)
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
        self.assertEqual(14 * header_size(), os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(self.fork_path(9, 'I', 'J'), chain_l.path())
        self.assertEqual(3 * header_size(), os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(self.fork_path(6, 'F', 'O'), chain_u.path())
        self.assertEqual(7 * header_size(), os.stat(chain_u.path()).st_size)
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
        self.assertEqual(12 * header_size(), os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(self.fork_path(9, 'I', 'J'), chain_l.path())
        self.assertEqual(2 * header_size(), os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(self.fork_path(6, 'F', 'O'), chain_u.path())
        self.assertEqual(5 * header_size(), os.stat(chain_u.path()).st_size)

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
        # Servers send headers below KawpowActivationHeight (on mainnet only the
        # genesis, on testnet all of them) as 80 bytes and the rest as 120-byte
        # KAWPOW headers; on disk every header takes header_size() bytes.
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
        if sha256d_headers():
            self.assertEqual(9 * 80, len(chunk))
        else:
            self.assertEqual(80 + 8 * 120, len(chunk))
        # a header of the wrong size does not fit
        self.assertFalse(await chain_u.connect_chunk(0, (chunk + bytes(40)).hex()))
        self.assertEqual(-1, chain_u.height())
        self.assertTrue(await chain_u.connect_chunk(0, chunk.hex()))
        self.assertEqual(8, chain_u.height())
        self.assertEqual(9 * header_size(), os.stat(chain_u.path()).st_size)
        for height, label in enumerate(labels):
            self.assertEqual(self.HEADERS[label], chain_u.read_header(height))
            self.assertEqual(hash_header(self.HEADERS[label]), chain_u.get_hash(height))
        self.assertTrue(all([chain_u.can_connect(chain_u.read_header(i), False) for i in range(chain_u.height())]))

        # the chain keeps growing and forking header by header
        self._append_header(chain_u, self.HEADERS['R'])
        chain_l = chain_u.fork(self.HEADERS['G'])
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)

    async def test_connect_chunk_across_forkpoint(self):
        # Interface.sync_until requests chunks from a multiple of 2016, which
        # can be below the forkpoint of the chain it follows: that chain keeps
        # the headers from its forkpoint on.
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        for label in 'ABCDEFOPQ':
            self._append_header(chain_u, self.HEADERS[label])
        chain_l = chain_u.fork(self.HEADERS['G'])

        labels = 'DEFGHIJK'  # heights 3 to 10
        chunk = b''.join(self.RAW_HEADERS[x] for x in labels)
        self.assertTrue(await chain_l.connect_chunk(3, chunk.hex()))
        # chain_l (11 headers) became the best chain
        self.assertIs(chain_l, blockchain.get_best_chain())
        self.assertEqual(0, chain_l.forkpoint)
        self.assertEqual(11 * header_size(), os.stat(chain_l.path()).st_size)
        for height, label in enumerate('ABCDEFGHIJK'):
            self.assertEqual(self.HEADERS[label], chain_l.read_header(height))
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(3 * header_size(), os.stat(chain_u.path()).st_size)
        self.assertEqual(self.HEADERS['Q'], chain_u.read_header(8))

    async def test_no_mix_hash_check_on_test_networks(self):
        # test networks do not check PoW at all (and the DePIN testnet uses SHA256d)
        self.assertFalse(blockchain.mix_hash_check_required(10 ** 7))
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        with mock.patch.object(kawpow_full, 'verify') as verify:
            chunk = b''.join(self.RAW_HEADERS[x] for x in 'ABCDEFOPQ')
            self.assertTrue(await chain_u.connect_chunk(0, chunk.hex()))
            await blockchain.precheck_mix_hash(self.HEADERS['R'])
            self._append_header(chain_u, self.HEADERS['R'])
        verify.assert_not_called()

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


class TestBlockchainSha256d(TestBlockchain):
    """The tests of TestBlockchain with the headers of the testnet:
    80-byte SHA256d headers, stored as 80-byte records."""
    NET = NeuraiUnitTestNetSha256d
    RAW_HEADERS, HEADERS = make_header_tree(TestBlockchain.TREE, NET)
    EXPECTED_HASHES = {label: sha256d_hash(raw) for label, raw in RAW_HEADERS.items()}

    def test_header_size(self):
        self.assertTrue(sha256d_headers())
        self.assertEqual(80, header_size())
        with self.assertRaises(InvalidHeader):
            deserialize_header(self.RAW_HEADERS['B'] + bytes(40), 1)


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
        raw_genesis = "04000000000000000000000000000000000000000000000000000000000000000000000051595fe1fb519173c0bd75904e460872585a1d38579788d183cd60d993bf284b08063d64ffff001e92cf6c00"
        genesis = deserialize_header(bfh(raw_genesis), 0)
        self.assertEqual(constants.net.GENESIS, hash_header(genesis))
        Blockchain.verify_header(genesis, '00' * 32, Blockchain.bits_to_target(0x1e00ffff))
        # mainnet headers files store it zero-padded to a 120-byte record
        self.assertEqual(raw_genesis + '00' * 40, blockchain.serialize_header(genesis))
        self.assertEqual(genesis, deserialize_header(bfh(raw_genesis + '00' * 40), 0))

    def test_mainnet_header_records(self):
        self.assertFalse(sha256d_headers())
        self.assertEqual(HEADER_SIZE, header_size())
        self.assertEqual(self.valid_header, blockchain.serialize_header(self.header))
        # legacy headers below KawpowActivationHeight (the genesis), KAWPOW from it
        chunk = bfh(self.valid_header)
        self.assertEqual(chunk, Blockchain.chunk_to_records(1000000, chunk))
        legacy = bytes(range(80))
        self.assertEqual(legacy + bytes(40) + chunk, Blockchain.chunk_to_records(0, legacy + chunk))

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


class TestMixHashCheck(ElectrumTestCase):
    """Mainnet headers above the last checkpoint get their KAWPOW mix_hash
    recomputed from the DAG (kawpow_full), which kawpow.light_verify() trusts."""

    CP = 1870847

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(os.path.join(os.path.dirname(__file__), 'blockchain_mainnet_headers.json')) as f:
            data = json.load(f)
        cls.FIRST = data['first_height']
        cls.RAW = {cls.FIRST + i: bfh(raw) for i, raw in enumerate(data['headers'])}
        cls.LAST = max(cls.RAW)  # 1870857

    def setUp(self):
        super().setUp()
        self.assertEqual(self.CP, constants.net.max_checkpoint())
        blockchain._mix_results.clear()
        blockchain.blockchains = {}
        config = SimpleConfig({'electrum_path': self.electrum_path})
        blockchain.blockchains[constants.net.GENESIS] = self.chain = Blockchain(
            config=config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        # as a new client: a sparse headers file up to the checkpoint, here
        # with the headers needed by DGW for the first ones after it
        blockchain.init_headers_file_for_best_chain()
        self.chain.save_chunk(self.FIRST, b''.join(self.RAW[h] for h in range(self.FIRST, self.CP + 1)))
        self.assertEqual(self.CP, self.chain.height())
        self.verified = []  # (height, thread name) of the mix_hash computations
        real_verify = kawpow_full.verify

        def verify(height, *args):
            self.verified.append((height, threading.current_thread().name))
            return real_verify(height, *args)
        patcher = mock.patch.object(kawpow_full, 'verify', side_effect=verify)
        patcher.start()
        self.addCleanup(patcher.stop)

    def header(self, height: int, raw: bytes = None) -> dict:
        return deserialize_header(raw or self.RAW[height], height)

    def chunk(self, start: int, end: int, forged: dict = None) -> str:
        forged = forged or {}
        return b''.join(forged.get(h, self.RAW[h]) for h in range(start, end + 1)).hex()

    def forge(self, height: int):
        """The header at height with another mix_hash, as if the server had
        ground it until the light check meets the target, which costs no DAG
        work. That grinding is out of reach of a unit test at mainnet difficulty:
        returns the raw header and a patch making the light check accept it."""
        raw = self.RAW[height]
        forged = raw[:88] + sha256d(b'forged ' + raw)
        real_light_verify = kawpow.light_verify

        def light_verify(header_hash, mix_hash, nonce):
            if mix_hash == forged[88:120][::-1]:
                mix_hash = raw[88:120][::-1]
            return real_light_verify(header_hash, mix_hash, nonce)
        return forged, mock.patch.object(blockchain.kawpow, 'light_verify', side_effect=light_verify)

    def test_light_check_accepts_forged_header(self):
        forged, light_check = self.forge(self.LAST)
        with light_check:
            self.assertEqual(hash_header(self.header(self.LAST)), hash_header(self.header(self.LAST, forged)))
            Blockchain.verify_header(self.header(self.LAST, forged), hash_header(self.header(self.LAST - 1)),
                                     Blockchain.bits_to_target(self.header(self.LAST)['bits']))
            with self.assertRaisesRegex(InvalidHeader, "is not its KAWPOW mix"):
                blockchain.verify_mix_hash(self.header(self.LAST, forged))
        blockchain.verify_mix_hash(self.header(self.LAST))
        with self.assertRaisesRegex(InvalidHeader, "height mismatch"):
            blockchain.verify_mix_hash(dict(self.header(self.LAST), block_height=self.LAST + 1))

    async def test_chunk_above_checkpoint(self):
        self.assertTrue(await self.chain.connect_chunk(self.CP + 1, self.chunk(self.CP + 1, self.LAST)))
        self.assertEqual(self.LAST, self.chain.height())
        # the last header and one at random, off the event loop
        (random_height, thread1), (last_height, thread2) = self.verified
        self.assertIn(random_height, range(self.CP + 1, self.LAST))
        self.assertEqual(self.LAST, last_height)
        self.assertTrue(thread1.startswith('kawpow') and thread2.startswith('kawpow'))

    async def test_chunk_with_forged_last_header(self):
        forged, light_check = self.forge(self.LAST)
        with light_check:
            self.assertFalse(await self.chain.connect_chunk(
                self.CP + 1, self.chunk(self.CP + 1, self.LAST, {self.LAST: forged})))
        self.assertEqual(self.CP, self.chain.height())

    async def test_chunk_with_forged_header(self):
        height = self.CP + 5
        forged, light_check = self.forge(height)
        chunk = self.chunk(self.CP + 1, self.LAST, {height: forged})
        pick = lambda headers: next(h for h in headers if h['block_height'] == height)
        with light_check, mock.patch.object(blockchain.secrets, 'choice', side_effect=pick):
            self.assertFalse(await self.chain.connect_chunk(self.CP + 1, chunk))
        self.assertEqual(self.CP, self.chain.height())
        # the check is a sample: a forged header that is not picked goes through
        pick = lambda headers: headers[0]
        with light_check, mock.patch.object(blockchain.secrets, 'choice', side_effect=pick):
            self.assertTrue(await self.chain.connect_chunk(self.CP + 1, chunk))
        self.assertEqual(self.LAST, self.chain.height())

    async def test_headers_at_tip(self):
        self.assertTrue(await self.chain.connect_chunk(self.CP + 1, self.chunk(self.CP + 1, self.LAST - 1)))
        self.verified.clear()
        forged, light_check = self.forge(self.LAST)
        forged = self.header(self.LAST, forged)
        with light_check:
            self.assertTrue(self.chain.can_connect(forged, verify_mix=False))
            await blockchain.precheck_mix_hash(forged)
            self.assertFalse(self.chain.can_connect(forged))
            self.assertIsNone(blockchain.can_connect(forged))
        self.assertEqual([self.LAST], [h for h, _ in self.verified])
        self.verified.clear()
        header = self.header(self.LAST)
        await blockchain.precheck_mix_hash(header)
        self.assertTrue(self.chain.can_connect(header))
        self.assertIs(self.chain, blockchain.can_connect(header))
        # verified once, off the event loop, then taken from the cache
        self.assertEqual(1, len(self.verified))
        self.assertTrue(self.verified[0][1].startswith('kawpow'))
        # headers that do not connect are not verified
        self.verified.clear()
        await blockchain.precheck_mix_hash(self.header(self.LAST - 1))
        await blockchain.precheck_mix_hash(dict(header, prev_block_hash='00' * 32))
        self.assertEqual([], self.verified)

    async def test_checkpoint_region_is_not_verified(self):
        headers = [self.header(h) for h in range(self.CP - 2, self.CP + 1)]
        self.assertEqual([], blockchain.pick_chunk_headers_for_mix_check(headers))
        self.assertTrue(self.chain.can_connect(self.header(self.CP), check_height=False))
        await blockchain.precheck_mix_hash(self.header(self.CP))
        self.assertEqual([], self.verified)
        headers += [self.header(self.CP + 1), self.header(self.CP + 2)]
        self.assertEqual(headers[-2:], blockchain.pick_chunk_headers_for_mix_check(headers))
