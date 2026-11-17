import os
import time
import unittest

from . import ElectrumTestCase

from electrum.simple_config import SimpleConfig
from electrum.wallet import restore_wallet_from_text, Standard_Wallet, Abstract_Wallet
from electrum.invoices import PR_UNPAID, PR_PAID, PR_UNCONFIRMED, BaseInvoice, Invoice, Request, LN_EXPIRY_NEVER
from electrum.bip21 import BITCOIN_BIP21_URI_SCHEME, parse_bip21_URI
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.transaction import Transaction, PartialTxOutput
from electrum.util import TxMinedInfo, InvoiceError


class TestWalletPaymentRequests(ElectrumTestCase):
    """test 'incoming' invoices"""
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.wallet1_path = os.path.join(self.electrum_path, "somewallet1")
        self.wallet2_path = os.path.join(self.electrum_path, "somewallet2")
        self._orig_get_cur_time = BaseInvoice._get_cur_time

    def tearDown(self):
        super().tearDown()
        BaseInvoice._get_cur_time = staticmethod(self._orig_get_cur_time)

    def create_wallet2(self) -> Standard_Wallet:
        # Neurai has no SegWit: 'standard' (p2pkh) electrum seed
        text = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        d = restore_wallet_from_text(text, path=self.wallet2_path, gap_limit=2, config=self.config)
        wallet2 = d['wallet']  # type: Standard_Wallet
        # bootstrap wallet
        # synthetic non-segwit funding tx (unsigned input) paying 1999890 sat to
        # wallet2's first receiving address tNMaxQqYZkDxhK7HzdMeZW8BUCLBbZt3PG
        funding_tx = Transaction('020000000132515e6aade1b79ec7dd3bac0896d8b32c56195d23d07d48e21659cef24301560100000000fdffffff0112841e00000000001976a914a9435fa56c13fc7063880c458ef0f3ba1fca628b88acad951d00')
        funding_txid = funding_tx.txid()
        assert '1b8d7751279a00bfd8ab769a6786cd85d3061ecf66f219a2898cd4259ca7782d' == funding_txid
        wallet2.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)
        return wallet2

    @unittest.skip("Neurai has no Lightning")
    async def test_wallet_with_ln_creates_payreq_and_gets_paid_on_ln(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        # get paid on LN
        wallet1.lnworker.set_request_status(bytes.fromhex(pr.rhash), PR_PAID)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    @unittest.skip("Neurai has no Lightning")
    async def test_wallet_with_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertTrue(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_without_ln_creates_payreq_and_gets_paid_onchain(self):
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNone(wallet1.lnworker)
        self.assertFalse(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertFalse(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx gets mined
        wallet1.db.put('stored_height', 1010)
        tx_info = TxMinedInfo(height=1001,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01"*32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr))

    async def test_wallet_gets_paid_onchain_in_the_past(self):
        # Neurai has no SegWit nor Lightning: 'standard' electrum seed, wallet without lnworker
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=2, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        wallet1.db.put('stored_height', 1000)
        self.assertIsNone(wallet1.lnworker)
        self.assertFalse(wallet1.has_lightning())
        # create payreq
        addr = wallet1.get_unused_address()
        pr_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertFalse(pr.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        self.assertEqual(1000, pr.height)
        # get paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr.get_address(), pr.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        # tx mined in the past (before invoice creation)
        tx_info = TxMinedInfo(height=990,
                              timestamp=pr.get_time() + 100,
                              txpos=1,
                              header_hash="01" * 32)
        wallet1.adb.add_verified_tx(tx.txid(), tx_info)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))

    @unittest.skip("Neurai has no Lightning")
    async def test_wallet_reuse_unused_fallback_onchain_addr_when_getting_paid_with_lightning(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=5, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNotNone(wallet1.lnworker)
        self.assertTrue(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertTrue(pr1.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertEqual(addr1, pr1.get_address())
        self.assertFalse(pr1.has_expired())

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertNotEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertTrue(pr2.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertEqual(addr2, pr2.get_address())

        # pr1 gets paid on LN
        wallet1.lnworker.set_request_status(bytes.fromhex(pr1.rhash), PR_PAID)
        self.assertEqual(PR_PAID, wallet1.get_invoice_status(pr1))

        # create payreq3, which should auto-reuse addr1
        addr3 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr3)
        pr3_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr3, exp_delay=86400)
        pr3 = wallet1.get_request(pr3_key)
        self.assertTrue(pr3.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr3))
        self.assertEqual(addr3, pr3.get_address())

        # pr2 gets paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr2.get_address(), pr2.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))

        # create payreq4, which should not reuse addr2
        addr4 = wallet1.get_unused_address()
        self.assertEqual(3, len({addr1, addr2, addr3, addr4}))
        pr4_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr4, exp_delay=86400)
        pr4 = wallet1.get_request(pr4_key)
        self.assertTrue(pr4.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr4))
        self.assertEqual(addr4, pr4.get_address())

    async def test_wallet_reuse_addr_of_expired_request(self):
        # Neurai has no SegWit nor Lightning: 'standard' electrum seed, wallet without lnworker
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=3, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNone(wallet1.lnworker)
        self.assertFalse(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertFalse(pr1.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertEqual(addr1, pr1.get_address())
        self.assertFalse(pr1.has_expired())

        BaseInvoice._get_cur_time = lambda *args: time.time() + 100_000
        self.assertTrue(pr1.has_expired())

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertFalse(pr2.is_lightning())
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertEqual(addr2, pr2.get_address())
        self.assertFalse(pr2.has_expired())

    async def test_wallet_get_request_by_addr(self):
        # Neurai has no SegWit nor Lightning: 'standard' electrum seed, wallet without lnworker
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(text, path=self.wallet1_path, gap_limit=3, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        self.assertIsNone(wallet1.lnworker)
        self.assertFalse(wallet1.has_lightning())
        # create payreq1
        addr1 = wallet1.get_unused_address()
        pr1_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr1, exp_delay=86400)
        pr1 = wallet1.get_request(pr1_key)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr1))
        self.assertFalse(pr1.has_expired())
        self.assertEqual(pr1, wallet1.get_request_by_addr(addr1))

        BaseInvoice._get_cur_time = lambda *args: time.time() + 100_000
        self.assertTrue(pr1.has_expired())
        self.assertEqual(None, wallet1.get_request_by_addr(addr1))

        # create payreq2
        addr2 = wallet1.get_unused_address()
        self.assertEqual(addr1, addr2)
        pr2_key = wallet1.create_request(amount_sat=10000, asset=None, message="msg", address=addr2, exp_delay=86400)
        pr2 = wallet1.get_request(pr2_key)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr2))
        self.assertFalse(pr2.has_expired())
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))

        # pr2 gets paid onchain
        wallet2 = self.create_wallet2()  # type: Standard_Wallet
        outputs = [PartialTxOutput.from_address_and_value(pr2.get_address(), pr2.get_amount_sat())]
        tx = wallet2.mktx(outputs=outputs, fee=5000)
        wallet1.adb.receive_tx_callback(tx.txid(), tx, TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))

        # FIXME the expired pr should stay "expired" - this might require storing state for it (see #8061):
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr1))

        # now make both invoices be past their expiration date. pr2 should be unaffected.
        BaseInvoice._get_cur_time = lambda *args: time.time() + 200_000
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr2))
        self.assertEqual(pr2, wallet1.get_request_by_addr(addr1))


class TestBaseInvoice(ElectrumTestCase):
    TESTNET = True

    async def test_arg_validation(self):
        amount_sat = 10_000
        outputs = [PartialTxOutput.from_address_and_value("tT2cst8Wa1rHaQVBzfMBV3y9D9xQopsTop", amount_sat)]
        invoice = Invoice(
            asset=None,
            amount_msat=amount_sat * 1000,
            message="mymsg",
            time=1692716965,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            bip70=None,
            height=0,
            lightning_invoice=None,
        )
        # out of bounds: above Neurai's 21 billion coin supply (2.1e21 msat)
        with self.assertRaises(InvoiceError):
            invoice.amount_msat = 10**22
        with self.assertRaises(InvoiceError):
            invoice.set_amount_msat(10**22)
        with self.assertRaises(InvoiceError):
            invoice2 = Invoice(
                asset=None,
                amount_msat=10**22,
                message="mymsg",
                time=1692716965,
                exp=LN_EXPIRY_NEVER,
                outputs=outputs,
                bip70=None,
                height=0,
                lightning_invoice=None,
            )
        with self.assertRaises(TypeError):
            invoice.time = "asd"
        with self.assertRaises(TypeError):
            invoice.exp = "asd"



class TestRequestBip21URI(ElectrumTestCase):

    def _request(self, outputs, *, asset=None, amount_msat=0):
        return Request(
            asset=asset,
            amount_msat=amount_msat,
            message="",
            time=1692716965,
            exp=0,
            outputs=outputs,
            bip70=None,
            height=0,
            payment_hash=None,
        )

    def test_lightning_only_uri_uses_neurai_scheme(self):
        # used to be "nuerai:?lightning=..."
        req = self._request([])
        self.assertEqual(f"{BITCOIN_BIP21_URI_SCHEME}:?lightning=lnfake", req.get_bip21_URI(lightning_invoice='lnfake'))
        self.assertTrue(req.get_bip21_URI(lightning_invoice='lnfake').startswith('neurai:'))
        self.assertIsNone(req.get_bip21_URI())

    def test_onchain_uri(self):
        addr = 'NTiZdUy7x61yrovNK6aFx8SvPV1R4D7ReW'
        req = self._request([PartialTxOutput.from_address_and_value(addr, 12345)], amount_msat=12345 * 1000)
        uri = req.get_bip21_URI()
        self.assertTrue(uri.startswith(f'neurai:{addr}?'), uri)
        self.assertEqual(addr, parse_bip21_URI(uri)['address'])
