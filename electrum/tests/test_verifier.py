# -*- coding: utf-8 -*-
import logging
import time

from electrum.bitcoin import hash_encode
from electrum.transaction import Transaction
from electrum.util import bfh
from electrum.verifier import SPV, InnerNodeOfSpvProofIsValidTx

from . import ElectrumTestCase


MERKLE_BRANCH = [
    'f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12',
    '6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520']

MERKLE_ROOT = '11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254'

VALID_64_BYTE_TX = ('0200000001cb659c5528311901a7aada7db817bd6e3ce2f05d1c62c385b7caad'
                    'b65fac75201234000000fabcdefa01abcd1234010000000405060708fabcdefa')
assert len(VALID_64_BYTE_TX) == 128


class VerifierTestCase(ElectrumTestCase):
    # these tests are regarding the attack described in
    # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html
    TESTNET = True

    def test_verify_ok_t_tx(self):
        """Actually mined 64 byte tx should not raise."""
        t_tx = Transaction(VALID_64_BYTE_TX)
        t_tx_hash = t_tx.txid()
        self.assertEqual(MERKLE_ROOT, SPV.hash_merkle_root(MERKLE_BRANCH, t_tx_hash, 3))

    def test_verify_fail_f_tx_odd(self):
        """Raise if inner node of merkle branch is valid tx. ('odd' fake leaf position)"""
        # first 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(VALID_64_BYTE_TX[:64]))
        fake_mbranch = [fake_branch_node] + MERKLE_BRANCH
        # last 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(VALID_64_BYTE_TX[64:]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 7)

    def test_verify_fail_f_tx_even(self):
        """Raise if inner node of merkle branch is valid tx. ('even' fake leaf position)"""
        # last 32 bytes of T encoded as hash
        fake_branch_node = hash_encode(bfh(VALID_64_BYTE_TX[64:]))
        fake_mbranch = [fake_branch_node] + MERKLE_BRANCH
        # first 32 bytes of T encoded as hash
        f_tx_hash = hash_encode(bfh(VALID_64_BYTE_TX[:64]))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            SPV.hash_merkle_root(fake_mbranch, f_tx_hash, 6)


class TestCheckpointChunkBackoff(ElectrumTestCase):

    async def test_chunk_that_does_not_connect_is_retried_later(self):
        results = [(False, 0), (False, 0), None, (True, 2016)]

        class FakeInterface:
            async def request_chunk(self, height, tip, *, can_return_early=False):
                return results.pop(0)

        spv = SPV.__new__(SPV)  # no network: only the chunk bookkeeping is exercised
        spv.logger = logging.getLogger('test_verifier')
        spv.interface = FakeInterface()
        spv._chunk_failures = {}

        await spv._request_checkpoint_chunk(4032)
        failures, next_try = spv._chunk_failures[4032]
        self.assertEqual(1, failures)
        self.assertAlmostEqual(2, next_try - time.monotonic(), delta=0.5)
        await spv._request_checkpoint_chunk(4032)
        failures, next_try = spv._chunk_failures[4032]
        self.assertEqual(2, failures)
        self.assertAlmostEqual(4, next_try - time.monotonic(), delta=0.5)
        await spv._request_checkpoint_chunk(4032)  # already in flight: nothing changes
        self.assertEqual(2, spv._chunk_failures[4032][0])
        await spv._request_checkpoint_chunk(4032)
        self.assertNotIn(4032, spv._chunk_failures)
