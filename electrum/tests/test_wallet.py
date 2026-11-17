import shutil
import tempfile
import sys
import os
import json
from decimal import Decimal
import time
from io import StringIO
import asyncio

from electrum.storage import WalletStorage
from electrum.wallet_db import FINAL_SEED_VERSION
from electrum.wallet import (Abstract_Wallet, Standard_Wallet, create_new_wallet,
                             restore_wallet_from_text, Imported_Wallet, Wallet)
from electrum.exchange_rate import ExchangeBase, FxThread
from electrum.util import TxMinedInfo, InvalidPassword
from electrum.bitcoin import COIN
from electrum.wallet_db import WalletDB
from electrum.simple_config import SimpleConfig
from electrum import util

from . import ElectrumTestCase


class FakeSynchronizer(object):

    def __init__(self, db):
        self.db = db
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(ElectrumTestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.user_dir = tempfile.mkdtemp()
        self.config = SimpleConfig({'electrum_path': self.user_dir})

        self.wallet_path = os.path.join(self.user_dir, "somewallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(WalletTestCase, self).tearDown()
        shutil.rmtree(self.user_dir)
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout


class TestWalletStorage(WalletTestCase):

    def test_read_dictionary_from_file(self):

        # the fork dropped Electrum's legacy (pre-seed_version) wallet formats,
        # so a readable wallet file must carry a seed_version
        some_dict = {"a":"b", "c":"d", "seed_version": FINAL_SEED_VERSION}
        contents = json.dumps(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path)
        db = WalletDB(storage.read(), storage=storage, manual_upgrades=True)
        self.assertEqual("b", db.get("a"))
        self.assertEqual("d", db.get("c"))

    def test_write_dictionary_to_file(self):

        storage = WalletStorage(self.wallet_path)
        db = WalletDB('', storage=storage, manual_upgrades=True)

        some_dict = {
            u"a": u"b",
            u"c": u"d",
            u"seed_version": FINAL_SEED_VERSION}

        for key, value in some_dict.items():
            db.put(key, value)
        db.write()

        with open(self.wallet_path, "r") as f:
            contents = f.read()
        d = json.loads(contents)
        for key, value in some_dict.items():
            self.assertEqual(d[key], value)

class FakeExchange(ExchangeBase):
    def __init__(self, rate):
        super().__init__(lambda self: None, lambda self: None)
        self._quotes = {'TEST': rate}
        self._quotes_timestamp = float("inf")  # spot price from the far future never becomes stale :P

class FakeFxThread:
    def __init__(self, exchange):
        self.exchange = exchange
        self.ccy = 'TEST'

    remove_thousands_separator = staticmethod(FxThread.remove_thousands_separator)
    timestamp_rate = FxThread.timestamp_rate
    ccy_amount_str = FxThread.ccy_amount_str
    history_rate = FxThread.history_rate

class FakeADB:
    def get_tx_height(self, txid):
        # because we use a current timestamp, and history is empty,
        # FxThread.history_rate will use spot prices
        return TxMinedInfo(height=10, conf=10, timestamp=int(time.time()), header_hash='def')

class FakeWallet:
    def __init__(self, fiat_value):
        super().__init__()
        self.fiat_value = fiat_value
        # empty data creates a fresh db (a "{}" db has no seed_version, which the fork does not accept)
        self.db = WalletDB("", storage=None, manual_upgrades=True)
        self.adb = FakeADB()
        self.db.transactions = self.db.verified_tx = {'abc':'Tx'}

    default_fiat_value = Abstract_Wallet.default_fiat_value
    price_at_timestamp = Abstract_Wallet.price_at_timestamp
    class storage:
        put = lambda self, x: None

txid = 'abc'
ccy = 'TEST'

class TestFiat(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        self.value_sat = COIN
        self.fiat_value = {}
        self.wallet = FakeWallet(fiat_value=self.fiat_value)
        self.fx = FakeFxThread(FakeExchange(Decimal('1000.001')))
        default_fiat = Abstract_Wallet.default_fiat_value(self.wallet, txid, self.fx, self.value_sat)
        self.assertEqual(Decimal('1000.001'), default_fiat)
        # the fork shows fiat amounts with 3 more decimals than the currency's precision (XNA is cheap)
        self.assertEqual('1 000.00100', self.fx.ccy_amount_str(default_fiat, add_thousands_sep=True))

    def test_save_fiat_and_reset(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1000.01', self.fx, self.value_sat))
        saved = self.fiat_value[ccy][txid]
        self.assertEqual('1 000.01000', self.fx.ccy_amount_str(Decimal(saved), add_thousands_sep=True))
        self.assertEqual(True,       Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(txid, self.fiat_value[ccy])
        # even though we are not setting it to the exact fiat value according to the exchange rate, precision is truncated away
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1 000.001002', self.fx, self.value_sat))

    def test_too_high_precision_value_resets_with_no_saved_value(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1 000.001', self.fx, self.value_sat))

    def test_empty_resets(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)

    def test_save_garbage(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, 'garbage', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)


class TestCreateRestoreWallet(WalletTestCase):

    async def test_create_new_wallet(self):
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = create_new_wallet(path=self.wallet_path,
                              passphrase=passphrase,
                              password=password,
                              encrypt_file=encrypt_file,
                              gap_limit=1,
                              config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet

        # (no lightning initialization check: Neurai has no Lightning)

        wallet.check_password(password)
        self.assertEqual(passphrase, wallet.keystore.get_passphrase(password))
        self.assertEqual(d['seed'], wallet.keystore.get_seed(password))
        self.assertEqual(encrypt_file, wallet.storage.is_encrypted())

    async def test_restore_wallet_from_text_mnemonic(self):
        # Neurai has no SegWit: use a 'standard' (p2pkh) electrum seed
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = restore_wallet_from_text(text,
                                     path=self.wallet_path,
                                     passphrase=passphrase,
                                     password=password,
                                     encrypt_file=encrypt_file,
                                     gap_limit=1,
                                     config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(passphrase, wallet.keystore.get_passphrase(password))
        self.assertEqual(text, wallet.keystore.get_seed(password))
        self.assertEqual(encrypt_file, wallet.storage.is_encrypted())
        self.assertEqual('NQHJsmJrAtLkeJVMXV2seHzdGr74usKeob', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_no_storage(self):
        # Neurai has no SegWit: use a 'standard' (p2pkh) electrum seed
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text(
            text,
            path=None,
            gap_limit=1,
            config=self.config,
        )
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(None, wallet.storage)
        self.assertEqual(text, wallet.keystore.get_seed(None))
        self.assertEqual('NhHj5eaHBV3hyoa6Md4zha2jvghGiwPqhb', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xpub(self):
        # upstream's zpub re-encoded with 'standard' version bytes: same key, p2pkh addresses
        text = 'xpub69K7C1tFttYMBmSkcnVvxdCykmodiQUA1SwfUA5f5FsvA2vCDcYfrqRPtih6cPfT7xsZsYsDJaa9GWJj8Uytas99WPSgGv8iv5RRWSgCK5a'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_public_key())
        self.assertEqual('NTmh4n3hNBKQxSjgptZ11h9HNE8n84vHN7', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xkey_that_is_also_a_valid_electrum_seed_by_chance(self):
        # Neurai has no SegWit (the upstream key is a yprv). This xprv is child m/90' of the xprv in
        # test_restore_wallet_from_text_xprv and happens to also be a valid 'standard' electrum seed.
        text = 'xprv9w4VnmYQZkrceSR5pNCKvjseAwo14kAUAzgq3v1XXHCqkV5rtZGTBP82GTpv4AYa15YhbAGoDQiQyyk6XdpDR7h3oUhMDj4chrWsTfwD1RV'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('Ngb9Z5KcpKCmtk2jBPkgDyn9eCEQTqftmn', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xprv(self):
        # upstream's zprv re-encoded with 'standard' version bytes: same key, p2pkh addresses
        text = 'xprv9vKknWMN4Wz3yHNHWkxvbVGFCjy9JwkJeE24fmg3WvLwHEb3g5ERK36v3TJyxMJgK6QuRyiVLdA39zj78hFQDPwxyHizuYEnn1qZGbwoNAw'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('NTmh4n3hNBKQxSjgptZ11h9HNE8n84vHN7', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_addresses(self):
        text = 'NTmh4n3hNBKQxSjgptZ11h9HNE8n84vHN7 NZpF2ESyuMR8mAdpRzY3ADajZc7GDcP2Qv'
        d = restore_wallet_from_text(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        self.assertEqual('NTmh4n3hNBKQxSjgptZ11h9HNE8n84vHN7', wallet.get_receiving_addresses()[0])
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('NZpF2ESyuMR8mAdpRzY3ADajZc7GDcP2Qv')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))

    async def test_restore_wallet_from_text_privkeys(self):
        text = 'p2pkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL p2pkh:L24GxnN7NNUAfCXA6hFzB1jt59fYAAiFZMcLaJ2ZSawGpM3uqhb1'
        d = restore_wallet_from_text(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        addr0 = wallet.get_receiving_addresses()[0]
        self.assertEqual('NTmh4n3hNBKQxSjgptZ11h9HNE8n84vHN7', addr0)
        self.assertEqual('p2pkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL',
                         wallet.export_private_key(addr0, password=None))
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('NZpF2ESyuMR8mAdpRzY3ADajZc7GDcP2Qv')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))


class TestWalletPassword(WalletTestCase):
    # The fixtures are upstream's seed_version 13 wallet files (same keys) written in the fork's
    # wallet format (seed_version 1, no storage upgrades) with Neurai addresses.

    async def test_update_password_of_imported_wallet(self):
        wallet_str = '{"addr_history":{"NN12VcpkteedHQ2Lt3c4GuKKkKfe7dAUym":[],"NQ7wQS8wHsRk2PFHvDTgwvVP9DsFjF4rMJ":[],"NZsd4myxvRpPfSLJ5uHkt1B5u4vvYNj37A":[]},"addresses":{"NN12VcpkteedHQ2Lt3c4GuKKkKfe7dAUym":{"pubkey":"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5","type":"p2pkh"},"NQ7wQS8wHsRk2PFHvDTgwvVP9DsFjF4rMJ":{"pubkey":"04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2","type":"p2pkh"},"NZsd4myxvRpPfSLJ5uHkt1B5u4vvYNj37A":{"pubkey":"0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f","type":"p2pkh"}},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq"},"type":"imported"},"seed_version":1,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"imported","winpos-qt":[100,100,840,405]}'
        storage = WalletStorage(self.wallet_path)
        db = WalletDB(wallet_str, storage=storage, manual_upgrades=False)
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")

        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    async def test_update_password_of_standard_wallet(self):
        wallet_str = '''{"addr_history":{"NL7jt1SHova8Vi6EZ3xYmZTqt73irDGoJh":[],"NM9AsWnajErFFHZ9QeNhWBcc6jrfyScZFu":[],"NMdPEo3fDduZDuSwv6VyffCygPUfokPJux":[],"NNCRCaTnFTRssTeaYLkoFYvKmfGA55atdL":[],"NNfELG5QwPzZ3wbCnZfmZz45GoEXWzZ9pZ":[],"NPNdEbWyus5tEQred1NYUp7z22V6w76ds1":[],"NPbjNiLkmgLRtuuDbfww46mHp29eN8M794":[],"NQAF63ihWSTTC73oENnpZFFMxn14feZL65":[],"NSiHBhSRfFLXnC8Tcup3d7dnAM71VrJ9L4":[],"NTcLoCXqczArj4gcttuKfTaB2Z1nrW9WbD":[],"NTh7a1kTNKsdcg1egRs7wUya4krsVDLXwJ":[],"NUV7KKTWHYmowBLJvjNaBiorfgWQgxzDbE":[],"NUu1un2cUAEUAPWhuCr6agbuL457chDcPf":[],"NUxVdXic3VCq7u9iGrYkyPc3stDJwSyGV5":[],"NYpntT5kDXtRwj2X2jPYnHKS8kpCSTR3sS":[],"NYywsCAaT4tUFMv9aRUnU7T3CgDTZydhWf":[],"NbNBdVYmEiV1v9ZmZc9j9onyevGo3Ekwxv":[],"NbRosaFxoU1GPrcGQ8rh34P5t92nDYeWjW":[],"Nbck1hdhseBGif2ST2xFGbZKgh3RUJMp1S":[],"NczReECbLWD8a8bXPYPnLeeiNz9rJCchbx":[],"NdRwdkYFwGRfoSsD8jDBcZq2WrUeu1ugYo":[],"NeKG9NmK32qbrKfun7xdXraJi4BcEbFCK4":[],"NeivkRQHxSFFGhepGBVUVEfvWqkugWp4xU":[],"NekTR9KuTA7MaaLTrqtDTVakWmPsPAJ9g2":[],"Ngv59yEpGff3R8Ro6jTPryNyzu8bj4PRQs":[],"Nig6UwWG6rnGzNnvA1ShWegZCoUhPP2cKf":[]},"addresses":{"change":["Nbck1hdhseBGif2ST2xFGbZKgh3RUJMp1S","NbNBdVYmEiV1v9ZmZc9j9onyevGo3Ekwxv","NQAF63ihWSTTC73oENnpZFFMxn14feZL65","NUxVdXic3VCq7u9iGrYkyPc3stDJwSyGV5","NUu1un2cUAEUAPWhuCr6agbuL457chDcPf","NdRwdkYFwGRfoSsD8jDBcZq2WrUeu1ugYo"],"receiving":["NPbjNiLkmgLRtuuDbfww46mHp29eN8M794","NNCRCaTnFTRssTeaYLkoFYvKmfGA55atdL","NUV7KKTWHYmowBLJvjNaBiorfgWQgxzDbE","NczReECbLWD8a8bXPYPnLeeiNz9rJCchbx","Nig6UwWG6rnGzNnvA1ShWegZCoUhPP2cKf","NNfELG5QwPzZ3wbCnZfmZz45GoEXWzZ9pZ","NeKG9NmK32qbrKfun7xdXraJi4BcEbFCK4","NM9AsWnajErFFHZ9QeNhWBcc6jrfyScZFu","NMdPEo3fDduZDuSwv6VyffCygPUfokPJux","NPNdEbWyus5tEQred1NYUp7z22V6w76ds1","NekTR9KuTA7MaaLTrqtDTVakWmPsPAJ9g2","NSiHBhSRfFLXnC8Tcup3d7dnAM71VrJ9L4","NYywsCAaT4tUFMv9aRUnU7T3CgDTZydhWf","NTcLoCXqczArj4gcttuKfTaB2Z1nrW9WbD","NeivkRQHxSFFGhepGBVUVEfvWqkugWp4xU","NTh7a1kTNKsdcg1egRs7wUya4krsVDLXwJ","NL7jt1SHova8Vi6EZ3xYmZTqt73irDGoJh","NYpntT5kDXtRwj2X2jPYnHKS8kpCSTR3sS","NbRosaFxoU1GPrcGQ8rh34P5t92nDYeWjW","Ngv59yEpGff3R8Ro6jTPryNyzu8bj4PRQs"]},"keystore":{"seed":"cereal wise two govern top pet frog nut rule sketch bundle logic","seed_type":"standard","type":"bip32","xprv":"xprv9s21ZrQH143K29XjRjUs6MnDB9wXjXbJP2kG1fnRk8zjdDYWqVkQYUqaDtgZp5zPSrH5PZQJs8sU25HrUgT1WdgsPU8GbifKurtMYg37d4v","xpub":"xpub661MyMwAqRbcEdcCXm1sTViwjBn28zK9kFfrp4C3JUXiW1sfP34f6HA45B9yr7EH5XGzWuTfMTdqpt9XPrVQVUdgiYb5NW9m8ij1FSZgGBF"},"seed_version":1,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[619,310,840,405]}'''
        storage = WalletStorage(self.wallet_path)
        db = WalletDB(wallet_str, storage=storage, manual_upgrades=False)
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    async def test_update_password_with_app_restarts(self):
        wallet_str = '{"addr_history":{"NN12VcpkteedHQ2Lt3c4GuKKkKfe7dAUym":[],"NQ7wQS8wHsRk2PFHvDTgwvVP9DsFjF4rMJ":[],"NZsd4myxvRpPfSLJ5uHkt1B5u4vvYNj37A":[]},"addresses":{"NN12VcpkteedHQ2Lt3c4GuKKkKfe7dAUym":{"pubkey":"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5","type":"p2pkh"},"NQ7wQS8wHsRk2PFHvDTgwvVP9DsFjF4rMJ":{"pubkey":"04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2","type":"p2pkh"},"NZsd4myxvRpPfSLJ5uHkt1B5u4vvYNj37A":{"pubkey":"0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f","type":"p2pkh"}},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq"},"type":"imported"},"seed_version":1,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"imported","winpos-qt":[100,100,840,405]}'
        storage = WalletStorage(self.wallet_path)
        db = WalletDB(wallet_str, storage=storage, manual_upgrades=False)
        wallet = Wallet(db, config=self.config)
        await wallet.stop()

        storage = WalletStorage(self.wallet_path)
        # if storage.is_encrypted():
        #     storage.decrypt(password)
        db = WalletDB(storage.read(), storage=storage, manual_upgrades=False)
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")
