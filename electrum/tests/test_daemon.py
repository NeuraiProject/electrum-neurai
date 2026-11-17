import os
from typing import Optional, Iterable

from electrum.daemon import Daemon
from electrum.ipfs_db import IPFSDB
from electrum.simple_config import SimpleConfig
from electrum.wallet import restore_wallet_from_text
from electrum import util

from . import ElectrumTestCase, as_testnet


class TestUnifiedPassword(ElectrumTestCase):
    config: 'SimpleConfig'

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.WALLET_USE_SINGLE_PASSWORD = True
        self.config.NETWORK_OFFLINE = True

        self.wallet_dir = os.path.dirname(self.config.get_wallet_path())
        assert "wallets" == os.path.basename(self.wallet_dir)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        # the Qt GUI sets up the IPFS metadata db before the daemon runs; Daemon.stop() saves it
        IPFSDB.initialize(self.config.get_ipfs_data_path(), self.config.get_ipfs_raw_path())
        self.daemon = Daemon(config=self.config, listen_jsonrpc=False)
        assert self.daemon.network is None

    async def asyncTearDown(self):
        await self.daemon.stop()
        await super().asyncTearDown()

    def _restore_wallet_from_text(self, text, *, password: Optional[str], encrypt_file: bool = None) -> str:
        """Returns path for created wallet."""
        basename = util.get_new_wallet_name(self.wallet_dir)
        path = os.path.join(self.wallet_dir, basename)
        wallet_dict = restore_wallet_from_text(
            text,
            path=path,
            password=password,
            encrypt_file=encrypt_file,
            gap_limit=2,
            config=self.config,
        )
        # We return the path instead of the wallet object, as extreme
        # care would be needed to use the wallet object directly:
        # Unless the daemon knows about it, daemon._load_wallet might create a conflicting wallet object
        # for the same fs path, and there would be two wallet objects contending for the same file.
        return path

    def _run_post_unif_sanity_checks(self, paths: Iterable[str], *, password: str):
        for path in paths:
            w = self.daemon.load_wallet(path, password)
            self.assertIsNotNone(w)
            w.check_password(password)
            self.assertTrue(w.has_storage_encryption())
            if w.can_have_keystore_encryption():
                self.assertTrue(w.has_keystore_encryption())
            if w.has_seed():
                self.assertIsInstance(w.get_seed(password), str)
        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password=password, wallet_dir=self.wallet_dir)
        self.assertEqual((True, True), (can_be_unified, is_unified))

    # "zt" and "x8" are short strings that happen to be valid "standard" (p2pkh)
    # Electrum seeds. Neurai has no SegWit, so no segwit seeds here.

    # "cannot unify pw" tests --->

    async def test_cannot_unify_two_std_wallets_both_have_ks_and_sto_enc(self):
        path1 = self._restore_wallet_from_text("zt", password="123456", encrypt_file=True)
        path2 = self._restore_wallet_from_text("x8",  password="asdasd", encrypt_file=True)
        with open(path1, "rb") as f:
            raw1_before = f.read()
        with open(path2, "rb") as f:
            raw2_before = f.read()

        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((False, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertFalse(is_unified)
        # verify that files on disk haven't changed:
        with open(path1, "rb") as f:
            raw1_after = f.read()
        with open(path2, "rb") as f:
            raw2_after = f.read()
        self.assertEqual(raw1_before, raw1_after)
        self.assertEqual(raw2_before, raw2_after)

    async def test_cannot_unify_mixed_wallets(self):
        path1 = self._restore_wallet_from_text("zt", password="123456", encrypt_file=True)
        path2 = self._restore_wallet_from_text("zt",  password="asdasd", encrypt_file=False)
        path3 = self._restore_wallet_from_text("zt",  password=None)
        with open(path1, "rb") as f:
            raw1_before = f.read()
        with open(path2, "rb") as f:
            raw2_before = f.read()
        with open(path3, "rb") as f:
            raw3_before = f.read()

        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((False, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertFalse(is_unified)
        # verify that files on disk haven't changed:
        with open(path1, "rb") as f:
            raw1_after = f.read()
        with open(path2, "rb") as f:
            raw2_after = f.read()
        with open(path3, "rb") as f:
            raw3_after = f.read()
        self.assertEqual(raw1_before, raw1_after)
        self.assertEqual(raw2_before, raw2_after)
        self.assertEqual(raw3_before, raw3_after)

    # "can unify pw" tests --->

    async def test_can_unify_two_std_wallets_both_have_ks_and_sto_enc(self):
        path1 = self._restore_wallet_from_text("zt", password="123456", encrypt_file=True)
        path2 = self._restore_wallet_from_text("x8",  password="123456", encrypt_file=True)
        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((True, True), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertTrue(is_unified)
        self._run_post_unif_sanity_checks([path1, path2], password="123456")

    async def test_can_unify_two_std_wallets_one_has_ks_enc_other_has_both_enc(self):
        path1 = self._restore_wallet_from_text("zt", password="123456", encrypt_file=True)
        path2 = self._restore_wallet_from_text("x8",  password="123456", encrypt_file=False)
        with open(path2, "rb") as f:
            raw2_before = f.read()

        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((True, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertTrue(is_unified)
        self._run_post_unif_sanity_checks([path1, path2], password="123456")
        # verify that file at path2 changed:
        with open(path2, "rb") as f:
            raw2_after = f.read()
        self.assertNotEqual(raw2_before, raw2_after)

    async def test_can_unify_two_std_wallets_one_without_password(self):
        path1 = self._restore_wallet_from_text("zt", password=None)
        path2 = self._restore_wallet_from_text("x8",  password="123456", encrypt_file=True)
        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((True, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertTrue(is_unified)
        self._run_post_unif_sanity_checks([path1, path2], password="123456")

    @as_testnet
    async def test_can_unify_large_folder_yet_to_be_unified(self):
        paths = []
        # seed
        paths.append(self._restore_wallet_from_text("zt", password="123456", encrypt_file=True))
        paths.append(self._restore_wallet_from_text("zt", password="123456", encrypt_file=False))
        paths.append(self._restore_wallet_from_text("zt", password=None))
        # xpub
        xpub = "tpubD6NzVbkrYhZ4XvPFMZA3a4vojyKt7WFyBFqVFGDVkZbwyaR8NZAH8ntCU6ME6axRUyWQUbC5bFEncujLVWSpHqmGD3vThP59Demj79GXSb5"
        paths.append(self._restore_wallet_from_text(xpub, password="123456", encrypt_file=True))
        paths.append(self._restore_wallet_from_text(xpub, password="123456", encrypt_file=False))
        paths.append(self._restore_wallet_from_text(xpub, password=None))
        # xprv
        xprv = "tprv8ZgxMBicQKsPeTMTTuVTAfGhAwowxB54bxEhxkBCLHoZ96AMkALgxJGLHwnXGHRZAWDvtdhJM9W57ZWsuK1F2YWVV5SBi48VkuehQXnKeL8"
        paths.append(self._restore_wallet_from_text(xprv, password="123456", encrypt_file=True))
        paths.append(self._restore_wallet_from_text(xprv, password="123456", encrypt_file=False))
        paths.append(self._restore_wallet_from_text(xprv, password=None))
        # WIFs
        wifs= "p2pkh:cV3BAxhdZoxYAf3evjW4oa4Yzyb9KshLkJRnHGN23yCENCR3ZWjT p2pkh:cUGt85d5imkv5tEkEYMtcS9NKZvCqPBPb3PHgCMAsN3hqdKCnrfC"
        paths.append(self._restore_wallet_from_text(wifs, password="123456", encrypt_file=True))
        paths.append(self._restore_wallet_from_text(wifs, password="123456", encrypt_file=False))
        paths.append(self._restore_wallet_from_text(wifs, password=None))
        # addrs
        addrs = "tCWPafzjEErkPqXTeTyhQ4XXsT6xUvJexM tD7CgBBmLnDfDKc6Gx33GqH9j4Bru5RkQB"
        paths.append(self._restore_wallet_from_text(addrs, password="123456", encrypt_file=True))
        paths.append(self._restore_wallet_from_text(addrs, password="123456", encrypt_file=False))
        paths.append(self._restore_wallet_from_text(addrs, password=None))
        # do unification
        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((True, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertTrue(is_unified)
        self._run_post_unif_sanity_checks(paths, password="123456")
