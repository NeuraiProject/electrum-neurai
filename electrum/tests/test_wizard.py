import os

from electrum import keystore, mnemonic
from electrum.base_wizard import BaseWizard, GoBack, ScriptTypeNotSupported, MSG_2FA_UNSUPPORTED
from electrum import constants
from electrum.bip32 import BIP32Node, normalize_bip32_derivation
from electrum.bitcoin import b58_address_to_hash160
from electrum.keystore import UnsupportedScriptType, bip39_to_seed
from electrum.simple_config import SimpleConfig
from electrum.wallet import Wallet
from electrum import bip39_recovery

from . import ElectrumTestCase


STANDARD_SEED = 'cram swing cover prefer miss modify ritual silly deliver chunk behind inform able'
SEGWIT_SEED = 'frost pig brisk excite novel report camera enlist axis nation novel desert'
TWOFA_SEED = 'science dawn member doll dutch real can brick knife deny drive list'
OLD_SEED = 'cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze'
BIP39_SEED = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

WIF = 'KxZcY47uGp9aVQAb6VVvuBs8SwHKgkSR2DbZUzjDzXf2N2GPhG9n'
WIF_ADDRESS = 'NYXixSUfyaWacJjEeHeXHinnCvZZnmjoUH'
OLD_MPK = keystore.from_seed(OLD_SEED, '').get_master_public_key()


def xkey(xtype: str, *, private: bool = False) -> str:
    node = BIP32Node.from_rootseed(b'\x07' * 32, xtype=xtype)
    return node.to_xprv() if private else node.to_xpub()


class _ScriptEnd(Exception):
    """The scripted wizard reached a dialog it has no answer for."""


class ScriptedWizard(BaseWizard):
    """BaseWizard whose GUI dialogs answer from a script, recording what they were shown."""

    def __init__(self, config, answers=()):
        BaseWizard.__init__(self, config, plugins=None)
        self.answers = list(answers)
        self.dialogs = []  # (name, kwargs)
        self.errors = []
        self.terminated = False

    def _dialog(self, name, run_next, **kwargs):
        self.dialogs.append((name, kwargs))
        if not self.answers:
            raise _ScriptEnd(name)
        answer = self.answers.pop(0)
        if not isinstance(answer, tuple):
            answer = (answer,)
        return run_next(*answer)

    def last_dialog(self, name):
        for n, kwargs in reversed(self.dialogs):
            if n == name:
                return kwargs
        raise AssertionError(f'dialog {name} not shown; shown: {[n for n, _ in self.dialogs]}')

    def choice_dialog(self, *, title, message, choices, run_next):
        return self._dialog('choice', run_next, choices=choices)

    def restore_seed_dialog(self, *, run_next, test):
        return self._dialog('restore_seed', run_next, test=test)

    def add_xpub_dialog(self, *, title, message, is_valid, run_next, allow_multi=False, show_wif_help=False):
        return self._dialog('add_xpub', run_next, is_valid=is_valid)

    def add_cosigner_dialog(self, *, run_next, index, is_valid):
        return self._dialog('add_cosigner', run_next, is_valid=is_valid)

    def derivation_and_script_type_gui_specific_dialog(self, *, run_next, choices, **kwargs):
        return self._dialog('derivation', run_next, choices=choices)

    def line_dialog(self, *, run_next, title, message, default, test, **kwargs):
        return self._dialog('line', run_next)

    def show_seed_dialog(self, *, run_next, seed_text):
        return self._dialog('show_seed', run_next, seed_text=seed_text)

    def confirm_seed_dialog(self, *, run_next, seed, test, seed_type):
        return self._dialog('confirm_seed', run_next, test=test)

    def request_password(self, *, run_next, force_disable_encrypt_cb=False):
        return self._dialog('password', run_next)

    def multisig_dialog(self, *, run_next):
        return self._dialog('multisig', run_next)

    def show_xpub_dialog(self, *, xpub, run_next):
        return self._dialog('show_xpub', run_next, xpub=xpub)

    def show_error(self, msg):
        self.errors.append(str(msg))

    def terminate(self, **kwargs):
        self.terminated = True


class TestWizardOnlyOffersUsableWallets(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def wizard(self, *answers) -> ScriptedWizard:
        return ScriptedWizard(self.config, answers)

    async def open_wallet(self, w: ScriptedWizard):
        self.assertTrue(w.terminated)
        path = os.path.join(self.electrum_path, 'wallet_%d' % len(os.listdir(self.electrum_path)))
        storage, db = w.create_storage(path)
        return Wallet(db, config=self.config)

    def test_wallet_types(self):
        w = self.wizard()
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        choices = [c[0] for c in w.last_dialog('choice')['choices']]
        self.assertEqual(['standard', 'multisig', 'imported'], choices)

    def test_2fa_wallet_type_is_refused(self):
        w = self.wizard()
        with self.assertRaises(GoBack):
            w.on_wallet_type('2fa')  # used to load the (missing) 'trustedcoin' plugin
        self.assertEqual([MSG_2FA_UNSUPPORTED], w.errors)
        self.assertNotIn('wallet_type', w.data)

    def test_restore_seed_dialog_refuses_segwit_and_2fa_seeds(self):
        w = self.wizard('standard', 'restore_from_seed')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        test = w.last_dialog('restore_seed')['test']
        self.assertTrue(test(STANDARD_SEED))
        self.assertTrue(test(OLD_SEED))
        self.assertFalse(test(SEGWIT_SEED))
        self.assertFalse(test(TWOFA_SEED))

    def test_cosigner_seed_dialog_refuses_segwit_2fa_and_old_seeds(self):
        w = self.wizard('multisig', (2, 2), 'restore_from_seed')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        test = w.last_dialog('restore_seed')['test']
        self.assertTrue(test(STANDARD_SEED))
        self.assertFalse(test(OLD_SEED))
        self.assertFalse(test(SEGWIT_SEED))
        self.assertFalse(test(TWOFA_SEED))

    def test_unsupported_electrum_seeds_give_a_message(self):
        for seed, expected in ((SEGWIT_SEED, 'SegWit'), (TWOFA_SEED, '2FA')):
            with self.subTest(seed=seed):
                w = self.wizard()
                w.wallet_type = 'standard'
                with self.assertRaises(GoBack):
                    w.on_restore_seed(seed, 'electrum', False)
                self.assertEqual(1, len(w.errors))
                self.assertIn(expected, w.errors[0])
                self.assertEqual([], w.keystores)

    async def test_restore_standard_electrum_seed(self):
        w = self.wizard('standard', 'restore_from_seed', (STANDARD_SEED, 'electrum', False), (None, False))
        w.run('new')
        self.assertEqual('standard', w.data['seed_type'])
        self.assertTrue(w.data['keystore']['xpub'].startswith('xpub'))
        self.assertNotIn('lightning_xprv', w.data)
        wallet = await self.open_wallet(w)
        self.assertEqual('p2pkh', wallet.txin_type)
        self.assertTrue(wallet.get_receiving_addresses()[0].startswith('N'))
        self.assertFalse(wallet.has_lightning())

    async def test_restore_bip39_seed_offers_only_legacy_derivations(self):
        w = self.wizard('standard', 'restore_from_seed', (BIP39_SEED, 'bip39', False))
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        choices = w.last_dialog('derivation')['choices']
        self.assertEqual(['standard'], [c[0] for c in choices])
        self.assertEqual(normalize_bip32_derivation("m/44'/0'/0'"), normalize_bip32_derivation(choices[0][2]))
        # a SegWit script type cannot be forced in either
        with self.assertRaises(ScriptTypeNotSupported):
            w.on_bip43(bip39_to_seed(BIP39_SEED, ''), "m/84'/0'/0'", 'p2wpkh', seed=BIP39_SEED)
        # the legacy one works
        w.answers = [(None, False)]
        w.on_bip43(bip39_to_seed(BIP39_SEED, ''), "m/44'/0'/0'", 'standard', seed=BIP39_SEED)
        self.assertEqual('bip39', w.data['seed_type'])
        wallet = await self.open_wallet(w)
        self.assertEqual('p2pkh', wallet.txin_type)
        self.assertTrue(wallet.get_receiving_addresses()[0].startswith('N'))

    def test_multisig_derivation_offers_only_p2sh(self):
        w = self.wizard('multisig', (2, 2), 'restore_from_seed', (BIP39_SEED, 'bip39', False))
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        choices = w.last_dialog('derivation')['choices']
        self.assertEqual(['standard'], [c[0] for c in choices])

    def test_master_key_dialog_refuses_segwit_keys(self):
        w = self.wizard('standard', 'restore_from_key')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        is_valid = w.last_dialog('add_xpub')['is_valid']
        self.assertTrue(is_valid(xkey('standard')))
        self.assertTrue(is_valid(xkey('standard', private=True)))
        self.assertTrue(is_valid(OLD_MPK))
        self.assertFalse(is_valid('not a key'))
        for xtype in ('p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh'):
            for private in (False, True):
                with self.subTest(xtype=xtype, private=private):
                    with self.assertRaises(UnsupportedScriptType) as ctx:
                        is_valid(xkey(xtype, private=private))
                    self.assertIn('SegWit', str(ctx.exception))

    def test_cosigner_key_dialog_refuses_segwit_keys(self):
        w = self.wizard('multisig', (2, 2), 'restore_from_key')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        is_valid = w.last_dialog('add_cosigner')['is_valid']
        self.assertTrue(is_valid(xkey('standard')))
        self.assertFalse(is_valid(OLD_MPK))
        for xtype in ('p2wsh', 'p2wsh-p2sh'):
            with self.assertRaises(UnsupportedScriptType):
                is_valid(xkey(xtype))

    def test_segwit_keystore_is_refused_with_a_message(self):
        # e.g. a key that got past the dialog, or a hardware wallet xpub
        for wallet_type in ('standard', 'multisig'):
            with self.subTest(wallet_type=wallet_type):
                w = self.wizard()
                w.wallet_type = wallet_type
                w.n = 2
                with self.assertRaises(_ScriptEnd):
                    w.on_restore_from_key(xkey('p2wpkh' if wallet_type == 'standard' else 'p2wsh'))
                self.assertEqual(1, len(w.errors))
                self.assertIn('SegWit', w.errors[0])
                self.assertEqual([], w.keystores)
                self.assertEqual('choice', w.dialogs[-1][0])  # back to choosing a keystore

    async def test_restore_from_xpub(self):
        w = self.wizard('standard', 'restore_from_key', xkey('standard'), (None, False))
        w.run('new')
        wallet = await self.open_wallet(w)
        self.assertEqual('p2pkh', wallet.txin_type)
        self.assertTrue(wallet.get_receiving_addresses()[0].startswith('N'))

    async def test_multisig_wallet_is_p2sh(self):
        w = self.wizard('multisig', (2, 2), 'restore_from_key', xkey('standard'), None,
                        'restore_from_key', BIP32Node.from_rootseed(b'\x08' * 32, xtype='standard').to_xpub(),
                        (None, False))
        w.run('new')
        wallet = await self.open_wallet(w)
        self.assertEqual('p2sh', wallet.txin_type)
        self.assertEqual(constants.net.ADDRTYPE_P2SH, b58_address_to_hash160(wallet.get_receiving_addresses()[0])[0])

    def test_import_dialog_refuses_segwit_wif_keys(self):
        w = self.wizard('imported')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        is_valid = w.last_dialog('add_xpub')['is_valid']
        self.assertTrue(is_valid(WIF))
        self.assertTrue(is_valid('p2pkh:' + WIF))
        self.assertTrue(is_valid('NTiZdUy7x61yrovNK6aFx8SvPV1R4D7ReW'))
        for prefix in ('p2wpkh', 'p2wpkh-p2sh'):
            with self.assertRaises(UnsupportedScriptType) as ctx:
                is_valid(f'{prefix}:{WIF}')
            self.assertIn('SegWit', str(ctx.exception))
        # one bad key spoils the list
        with self.assertRaises(UnsupportedScriptType):
            is_valid(f'{WIF}\np2wpkh:{WIF}')

    async def test_import_private_key(self):
        w = self.wizard('imported', WIF, (None, False))
        w.run('new')
        self.assertEqual({WIF_ADDRESS: {'type': 'p2pkh', 'pubkey': w.data['addresses'][WIF_ADDRESS]['pubkey']}},
                         w.data['addresses'])
        wallet = await self.open_wallet(w)
        self.assertEqual([WIF_ADDRESS], wallet.get_addresses())

    async def test_new_seed_is_standard_even_if_nosegwit_is_off(self):
        self.config.WIZARD_DONT_CREATE_SEGWIT = False
        w = self.wizard('standard', 'choose_seed_type')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        self.assertEqual('standard', w.seed_type)
        # what the seed dialog does when the user switches to an Electrum seed
        seed = mnemonic.Mnemonic('en').make_seed(seed_type=w.seed_type)
        self.assertEqual('standard', mnemonic.seed_type(seed))
        w.answers = [seed, (None, False)]  # confirm seed, password
        w.request_passphrase(seed, False, 'electrum')
        self.assertEqual('standard', w.data['seed_type'])
        self.assertNotIn('lightning_xprv', w.data)
        wallet = await self.open_wallet(w)
        self.assertEqual('p2pkh', wallet.txin_type)

    async def test_new_bip39_seed(self):
        w = self.wizard('standard', 'choose_seed_type')
        with self.assertRaises(_ScriptEnd):
            w.run('new')
        seed = w.last_dialog('show_seed')['seed_text']  # BIP39 by default
        w.answers = [seed, (None, False)]
        w.request_passphrase(seed, False, 'bip39')
        self.assertEqual('bip39', w.data['seed_type'])
        self.assertNotIn('lightning_xprv', w.data)
        self.assertTrue(w.data['keystore']['xpub'].startswith('xpub'))
        self.assertEqual(normalize_bip32_derivation("m/44'/0'/0'"), w.data['keystore']['derivation'])
        wallet = await self.open_wallet(w)
        self.assertEqual('p2pkh', wallet.txin_type)


class TestNeuraiKeyRestrictions(ElectrumTestCase):

    def test_supported_private_keys(self):
        self.assertTrue(keystore.is_supported_private_key(WIF))
        self.assertTrue(keystore.is_supported_private_key('p2pkh:' + WIF))
        self.assertFalse(keystore.is_supported_private_key('p2wpkh:' + WIF))
        self.assertFalse(keystore.is_supported_private_key('p2wpkh-p2sh:' + WIF))
        self.assertFalse(keystore.is_supported_private_key('garbage'))
        with self.assertRaises(UnsupportedScriptType):
            keystore.is_supported_private_key('p2wpkh:' + WIF, raise_on_error=True)
        self.assertIsNone(keystore.get_private_keys('p2wpkh:' + WIF))
        self.assertFalse(keystore.is_private_key_list(f'{WIF} p2wpkh-p2sh:{WIF}', allow_spaces_inside_key=False))

    def test_imported_keystore_refuses_segwit_keys(self):
        k = keystore.Imported_KeyStore({})
        for prefix in ('p2wpkh', 'p2wpkh-p2sh'):
            with self.assertRaises(UnsupportedScriptType):
                k.import_privkey(f'{prefix}:{WIF}', None)
        self.assertEqual({}, k.keypairs)  # nothing stored
        self.assertEqual('p2pkh', k.import_privkey(WIF, None)[0])

    def test_supported_master_keys(self):
        self.assertTrue(keystore.is_supported_master_key(xkey('standard')))
        self.assertTrue(keystore.is_supported_master_key(xkey('standard', private=True)))
        self.assertTrue(keystore.is_supported_master_key(OLD_MPK))
        for xtype in ('p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh'):
            self.assertFalse(keystore.is_supported_master_key(xkey(xtype)))
        self.assertFalse(keystore.is_supported_master_key('xpub'))

    def test_no_lightning_keys(self):
        # upstream derived Lightning keys from segwit seeds
        k = keystore.from_seed(SEGWIT_SEED, '')
        self.assertFalse(k.can_have_deterministic_lightning_xprv())
        k = keystore.from_seed(STANDARD_SEED, '')
        self.assertFalse(k.can_have_deterministic_lightning_xprv())


class TestBip39Recovery(ElectrumTestCase):

    def test_only_legacy_formats_are_scanned(self):
        formats = bip39_recovery.get_wallet_formats()
        self.assertTrue(formats)
        self.assertEqual({'p2pkh'}, {f['script_type'] for f in formats})

    async def test_account_discovery_does_not_fail_on_segwit_formats(self):
        root = BIP32Node.from_rootseed(bip39_to_seed(BIP39_SEED, ''), xtype='standard')
        get_account_xpub = lambda path: root.subkey_at_private_derivation(path).to_xpub()
        queried = []

        class FakeNetwork:
            async def get_history_for_scripthash(self, sh):
                queried.append(sh)
                return []

        accounts = await bip39_recovery.account_discovery(FakeNetwork(), get_account_xpub)
        self.assertEqual([], accounts)
        self.assertTrue(queried)
