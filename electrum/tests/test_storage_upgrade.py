import os
import json
from typing import Optional
import asyncio
import inspect

import electrum
from electrum.wallet_db import WalletDB, FINAL_SEED_VERSION
from electrum.wallet import Wallet
from electrum import constants
from electrum import util
from electrum.util import WalletFileException

from . import as_testnet
from .test_wallet import WalletTestCase


WALLET_FILES_DIR = os.path.join(os.path.dirname(__file__), "test_storage_upgrade")


# Neurai restarted the wallet file versioning: FINAL_SEED_VERSION is 1 and
# WalletDB.upgrade() has no upgrade steps. The client_1_x/2_x/3_x files are
# (Bitcoin) Electrum wallet files, with seed_version 4..18 or, for the oldest
# formats, no seed_version at all. The Neurai client has no upgrade path for
# them and must refuse to open them with a WalletFileException.
# Only the current Neurai format (client_0_2_2_*, seed_version 1) loads.

# TODO add other wallet types: 2fa, xpub-only
# TODO hw wallet with client version 2.6.x (single-, and multiacc)
class TestStorageUpgrade(WalletTestCase):

    def _get_wallet_str(self):
        test_method_name = inspect.stack()[1][3]
        assert isinstance(test_method_name, str)
        assert test_method_name.startswith("test_upgrade_from_")
        fname = test_method_name[len("test_upgrade_from_"):]
        test_vector_file = os.path.join(WALLET_FILES_DIR, fname)
        with open(test_vector_file, "r") as f:
            wallet_str = f.read()
        return wallet_str


##########

    async def test_upgrade_from_client_0_2_2_seeded(self):
        # current Neurai wallet file format: nothing to upgrade
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        self.assertEqual(FINAL_SEED_VERSION, db.get_seed_version())
        wallet = Wallet(db, config=self.config)
        self.assertEqual('NhHj5eaHBV3hyoa6Md4zha2jvghGiwPqhb', wallet.get_receiving_addresses()[0])
        self.assertEqual('NhHj5eaHBV3hyoa6Md4zha2jvghGiwPqhb', wallet.derive_address(0, 0))
        await wallet.stop()

    def test_other_client_storage_versions_explained(self):
        # Electrum-Neurai 0.1.x wrote storage version 49, before the reset to 1;
        # a version just above ours would come from a newer Electrum-Neurai
        for seed_version, hint in ((49, 'Electrum-Neurai 0.1.x'), (FINAL_SEED_VERSION + 1, 'too old')):
            wallet_json = json.dumps({'seed_version': seed_version, 'wallet_type': 'standard'})
            with self.subTest(seed_version=seed_version):
                with self.assertRaises(WalletFileException) as ctx:
                    self._load_db_from_json_string(wallet_json=wallet_json, manual_upgrades=False)
                self.assertIn(hint, str(ctx.exception))

    async def test_upgrade_from_client_1_9_8_seeded(self):
        """note: this wallet file is not valid json: it tests the ast.literal_eval()
        fallback in wallet_db.load_data()
        """
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    # TODO pre-2.0 mixed wallets are not split currently
    #async def test_upgrade_from_client_1_9_8_mixed(self):
    #    wallet_str = "{'addr_history':{'15V7MsQK2vjF5aEXLVG11qi2eZPZsXdnYc':[],'177hEYTccmuYH8u68pYfaLteTxwJrVgvJj':[],'1DjtUCcQwwzA3GSPA7Kd79PMnri7tLDPYC':[],'1PGEgaPG1XJqmuSj68GouotWeYkCtwo4wm':[],'1PAgpPxnL42Hp3cWxmSfdChPqqGiM8g7zj':[],'1DgrwN2JCDZ6uPMSvSz8dPeUtaxLxWM2kf':[],'1H3mPXHFzA8UbvhQVabcDjYw3CPb3djvxs':[],'1HocPduHmQUJerpdaLG8DnmxvnDCVQwWsa':[]},'accounts_expanded':{},'master_public_key':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb','use_encryption':False,'seed':'2605aafe50a45bdf2eb155302437e678','accounts':{0:{0:['1DjtUCcQwwzA3GSPA7Kd79PMnri7tLDPYC','1PAgpPxnL42Hp3cWxmSfdChPqqGiM8g7zj','177hEYTccmuYH8u68pYfaLteTxwJrVgvJj','1PGEgaPG1XJqmuSj68GouotWeYkCtwo4wm','15V7MsQK2vjF5aEXLVG11qi2eZPZsXdnYc'],1:['1H3mPXHFzA8UbvhQVabcDjYw3CPb3djvxs','1HocPduHmQUJerpdaLG8DnmxvnDCVQwWsa','1DgrwN2JCDZ6uPMSvSz8dPeUtaxLxWM2kf'],'mpk':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb'}},'imported_keys':{'15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA':'5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq','1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6':'L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U','1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr':'L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM'},'seed_version':4}"
    #    await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_0_4_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_0_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_0_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_0_4_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_1_1_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_2_0_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_3_2_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_4_3_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_5_4_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_6_4_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_6_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_6_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_6_4_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_7_18_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_7_18_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_7_18_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_7_18_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_7_18_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    # seed_version 13 is ambiguous
    # client 2.7.18 created wallets with an earlier "v13" structure
    # client 2.8.3 created wallets with a later "v13" structure
    # client 2.8.3 did not do a proper clean-slate upgrade
    # the wallet here was created in 2.7.18 with a couple privkeys imported
    # then opened in 2.8.3, after which a few other new privkeys were imported
    # it's in some sense in an "inconsistent" state
    async def test_upgrade_from_client_2_8_3_importedkeys_flawed_previous_upgrade_from_2_7_18(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_8_3_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_8_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_8_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_8_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_8_3_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_seeded(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_2_9_3_old_seeded_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_multisig(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_3_2_3_ledger_standard_keystore_changes(self):
        # see #6066 (the keystore checks need an upgraded wallet; this file is refused)
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    async def test_upgrade_from_client_2_9_3_importedkeys_keystore_changes(self):
        # see #6401 (the keystore checks need an upgraded wallet; this file is refused)
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_3_3_8_xpub_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        self._assert_wallet_file_rejected(wallet_str)

##########

    # note: no Plugins instance here. It was only needed to load hardware wallet
    #       keystores (e.g. Trezor), but every hardware wallet file in this module is
    #       refused before keystores are loaded. Its DaemonThread.on_stop() also needs
    #       electrum's global event loop, which unit tests do not create
    #       ("Exception in thread Plugins: event loop not created yet" on teardown).

    def _assert_wallet_file_rejected(self, wallet_json):
        for manual_upgrades in (True, False):
            with self.subTest(manual_upgrades=manual_upgrades):
                with self.assertRaises(WalletFileException):
                    self._load_db_from_json_string(wallet_json=wallet_json,
                                                   manual_upgrades=manual_upgrades)

    async def _upgrade_storage(self, wallet_json, accounts=1) -> Optional[WalletDB]:
        if accounts == 1:
            # test manual upgrades
            db = self._load_db_from_json_string(wallet_json=wallet_json,
                                                manual_upgrades=True)
            self.assertFalse(db.requires_split())
            if db.requires_upgrade():
                db.upgrade()
                await self._sanity_check_upgraded_db(db)
            # test automatic upgrades
            db2 = self._load_db_from_json_string(wallet_json=wallet_json,
                                                 manual_upgrades=False)
            await self._sanity_check_upgraded_db(db2)
            return db2
        else:
            db = self._load_db_from_json_string(wallet_json=wallet_json,
                                                manual_upgrades=True)
            self.assertTrue(db.requires_split())
            split_data = db.get_split_accounts()
            self.assertEqual(accounts, len(split_data))
            for item in split_data:
                data = json.dumps(item)
                new_db = WalletDB(data, storage=None, manual_upgrades=False)
                await self._sanity_check_upgraded_db(new_db)

    async def _sanity_check_upgraded_db(self, db):
        self.assertFalse(db.requires_split())
        self.assertFalse(db.requires_upgrade())
        wallet = Wallet(db, config=self.config)
        await wallet.stop()

    @staticmethod
    def _load_db_from_json_string(*, wallet_json, manual_upgrades):
        db = WalletDB(wallet_json, storage=None, manual_upgrades=manual_upgrades)
        return db
