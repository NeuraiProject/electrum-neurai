import copy
import os

from typing import List, TYPE_CHECKING, Tuple, NamedTuple, Any, Dict, Optional, Union

from electrum.logging import get_logger
from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB
from electrum.bip32 import normalize_bip32_derivation, xpub_type
from electrum import keystore
from electrum import bitcoin
from electrum.mnemonic import seed_type, unsupported_seed_type_message
from electrum.i18n import _
from electrum.util import UserFacingException


class WizardViewState(NamedTuple):
    view: Optional[str]
    wizard_data: Dict[str, Any]
    params: Dict[str, Any]

class AbstractWizard:
    # serve as a base for all UIs, so no qt
    # encapsulate wizard state
    # encapsulate navigation decisions, UI agnostic
    # encapsulate stack, go backwards
    # allow extend/override flow in subclasses e.g.
    # - override: replace 'next' value to own fn
    # - extend: add new keys to navmap, wire up flow by override

    _logger = get_logger(__name__)

    def __init__(self):
        self.navmap = {}

        self._current = WizardViewState(None, {}, {})
        self._stack = []  # type: List[WizardViewState]

    def navmap_merge(self, additional_navmap):
        # NOTE: only merges one level deep. Deeper dict levels will overwrite
        for k,v in additional_navmap.items():
            if k in self.navmap:
                self.navmap[k].update(v)
            else:
                self.navmap[k] = v

    # from current view and wizard_data, resolve the new view
    # returns WizardViewState tuple (view name, wizard_data, view params)
    # view name is the string id of the view in the nav map
    # wizard data is the (stacked) wizard data dict containing user input and choices
    # view params are transient, meant for extra configuration of a view (e.g. info
    #   msg in a generic choice dialog)
    # exception: stay on this view
    def resolve_next(self, view, wizard_data):
        assert view
        self._logger.debug(f'view={view}')
        assert view in self.navmap

        nav = self.navmap[view]

        if 'accept' in nav:
            # allow python scope to append to wizard_data before
            # adding to stack or finishing
            if callable(nav['accept']):
                nav['accept'](wizard_data)
            else:
                self._logger.error(f'accept handler for view {view} not callable')

        if 'next' not in nav:
            # finished
            self.finished(wizard_data)
            return (None, wizard_data, {})

        nexteval = nav['next']
        # simple string based next view
        if isinstance(nexteval, str):
            new_view = WizardViewState(nexteval, wizard_data, {})
        else:
            # handler fn based next view
            nv = nexteval(wizard_data)
            self._logger.debug(repr(nv))

            # append wizard_data and params if not returned
            if isinstance(nv, str):
                new_view = WizardViewState(nv, wizard_data, {})
            elif len(nv) == 1:
                new_view = WizardViewState(nv[0], wizard_data, {})
            elif len(nv) == 2:
                new_view = WizardViewState(nv[0], nv[1], {})
            else:
                new_view = nv

        self._stack.append(copy.deepcopy(self._current))
        self._current = new_view

        self._logger.debug(f'resolve_next view is {self._current.view}')
        self.log_stack(self._stack)

        return new_view

    def resolve_prev(self):
        prev_view = self._stack.pop()

        self._logger.debug(f'resolve_prev view is {prev_view}')
        self.log_stack(self._stack)

        self._current = prev_view
        return prev_view

    # check if this view is the final view
    def is_last_view(self, view, wizard_data):
        assert view
        assert view in self.navmap

        nav = self.navmap[view]

        if 'last' not in nav:
            return False

        lastnav = nav['last']
        # bool literal
        if isinstance(lastnav, bool):
            return lastnav
        elif callable(lastnav):
            # handler fn based
            l = lastnav(view, wizard_data)
            self._logger.debug(f'view "{view}" last: {l}')
            return l
        else:
            raise Exception(f'last handler for view {view} is not callable nor a bool literal')

    def finished(self, wizard_data):
        self._logger.debug('finished.')

    def reset(self):
        self._stack = []
        self._current = WizardViewState(None, {}, {})

    def log_stack(self, _stack):
        logstr = 'wizard stack:'
        stack = copy.deepcopy(_stack)
        i = 0
        for item in stack:
            self.sanitize_stack_item(item.wizard_data)
            logstr += f'\n{i}: {repr(item.wizard_data)}'
            i += 1
        self._logger.debug(logstr)

    def log_state(self, _current):
        current = copy.deepcopy(_current)
        self.sanitize_stack_item(current)
        self._logger.debug(f'wizard current: {repr(current)}')

    def sanitize_stack_item(self, _stack_item):
        sensitive_keys = ['seed', 'seed_extra_words', 'master_key', 'private_key_list', 'password']
        def sanitize(_dict):
            for item in _dict:
                if isinstance(_dict[item], dict):
                    sanitize(_dict[item])
                else:
                    if item in sensitive_keys:
                        _dict[item] = '<sensitive value removed>'
        sanitize(_stack_item)


class NewWalletWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon):
        AbstractWizard.__init__(self)
        self.navmap = {
            'wallet_name': {
                'next': 'wallet_type'
            },
            'wallet_type': {
                'next': self.on_wallet_type
            },
            'keystore_type': {
                'next': self.on_keystore_type
            },
            'create_seed': {
                'next': 'confirm_seed'
            },
            'confirm_seed': {
                'next': self.on_have_or_confirm_seed,
                'accept': self.maybe_master_pubkey,
                'last': lambda v,d: self.is_single_password() and not self.is_multisig(d)
            },
            'have_seed': {
                'next': self.on_have_or_confirm_seed,
                'accept': self.maybe_master_pubkey,
                'last': lambda v,d: self.is_single_password() and not self.is_bip39_seed(d) and not self.is_multisig(d)
            },
            'bip39_refine': {
                'next': lambda d: 'wallet_password' if not self.is_multisig(d) else 'multisig_cosigner_keystore',
                'accept': self.maybe_master_pubkey,
                'last': lambda v,d: self.is_single_password() and not self.is_multisig(d)
            },
            'have_master_key': {
                'next': lambda d: 'wallet_password' if not self.is_multisig(d) else 'multisig_cosigner_keystore',
                'accept': self.maybe_master_pubkey,
                'last': lambda v,d: self.is_single_password() and not self.is_multisig(d)
            },
            'multisig': {
                'next': 'keystore_type'
            },
            'multisig_cosigner_keystore': { # this view should set 'multisig_current_cosigner'
                'next': self.on_cosigner_keystore_type
            },
            'multisig_cosigner_key': {
                'next': lambda d: 'wallet_password' if self.has_all_cosigner_data(d) else 'multisig_cosigner_keystore',
                'last': lambda v,d: self.is_single_password() and self.has_all_cosigner_data(d)
            },
            'multisig_cosigner_seed': {
                'next': self.on_have_cosigner_seed,
                'last': lambda v,d: self.is_single_password() and self.has_all_cosigner_data(d)
            },
            'multisig_cosigner_bip39_refine': {
                'next': lambda d: 'wallet_password' if self.has_all_cosigner_data(d) else 'multisig_cosigner_keystore',
                'last': lambda v,d: self.is_single_password() and self.has_all_cosigner_data(d)
            },
            'imported': {
                'next': 'wallet_password',
                'last': lambda v,d: self.is_single_password()
            },
            'wallet_password': {
                'last': True
            }
        }
        self._daemon = daemon

    def start(self, initial_data=None):
        if initial_data is None:
            initial_data = {}
        self.reset()
        self._current = WizardViewState('wallet_name', initial_data, {})
        return self._current

    def is_single_password(self):
        raise NotImplementedError()

    def is_bip39_seed(self, wizard_data):
        return wizard_data.get('seed_variant') == 'bip39'

    def is_multisig(self, wizard_data):
        return wizard_data['wallet_type'] == 'multisig'

    def on_wallet_type(self, wizard_data):
        t = wizard_data['wallet_type']
        # no '2fa': the TrustedCoin plugin is not part of Electrum-Neurai
        return {
            'standard': 'keystore_type',
            'multisig': 'multisig',
            'imported': 'imported'
        }.get(t)

    def on_keystore_type(self, wizard_data):
        t = wizard_data['keystore_type']
        return {
            'createseed': 'create_seed',
            'haveseed': 'have_seed',
            'masterkey': 'have_master_key'
        }.get(t)

    def on_have_or_confirm_seed(self, wizard_data):
        if self.is_bip39_seed(wizard_data):
            return 'bip39_refine'
        elif self.is_multisig(wizard_data):
            return 'multisig_cosigner_keystore'
        else:
            return 'wallet_password'

    def maybe_master_pubkey(self, wizard_data):
        self._logger.info('maybe_master_pubkey')
        if self.is_bip39_seed(wizard_data) and 'derivation_path' not in wizard_data:
            self._logger.info('maybe_master_pubkey2')
            return

        wizard_data['multisig_master_pubkey'] = self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key()

    def on_cosigner_keystore_type(self, wizard_data):
        t = wizard_data['cosigner_keystore_type']
        return {
            'key': 'multisig_cosigner_key',
            'seed': 'multisig_cosigner_seed'
        }.get(t)

    def on_have_cosigner_seed(self, wizard_data):
        current_cosigner_data = wizard_data['multisig_cosigner_data'][str(wizard_data['multisig_current_cosigner'])]
        if self.has_all_cosigner_data(wizard_data):
            return 'wallet_password'
        elif current_cosigner_data['seed_type'] == 'bip39' and 'derivation_path' not in current_cosigner_data:
            return 'multisig_cosigner_bip39_refine'
        else:
            return 'multisig_cosigner_keystore'

    def has_all_cosigner_data(self, wizard_data):
        # number of items in multisig_cosigner_data is less than participants?
        if len(wizard_data['multisig_cosigner_data']) < (wizard_data['multisig_participants'] - 1):
            return False

        # if last cosigner uses bip39 seed, we still need derivation path
        current_cosigner_data = wizard_data['multisig_cosigner_data'][str(wizard_data['multisig_current_cosigner'])]
        if 'seed_type' in current_cosigner_data and current_cosigner_data['seed_type'] == 'bip39' and 'derivation_path' not in current_cosigner_data:
            return False

        return True

    def has_duplicate_masterkeys(self, wizard_data) -> bool:
        """Multisig wallets need distinct master keys. If True, need to prevent wallet-creation."""
        xpubs = []
        xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key())
        for cosigner in wizard_data['multisig_cosigner_data']:
            data = wizard_data['multisig_cosigner_data'][cosigner]
            xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], data).get_master_public_key())
        assert xpubs
        return len(xpubs) != len(set(xpubs))

    def has_heterogeneous_masterkeys(self, wizard_data) -> bool:
        """Multisig wallets need homogeneous master keys.
        All master keys need to be bip32, and e.g. Ypub cannot be mixed with Zpub.
        If True, need to prevent wallet-creation.
        """
        xpubs = []
        xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key())
        for cosigner in wizard_data['multisig_cosigner_data']:
            data = wizard_data['multisig_cosigner_data'][cosigner]
            xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], data).get_master_public_key())
        assert xpubs
        try:
            k_xpub_type = xpub_type(xpubs[0])
        except Exception:
            return True  # maybe old_mpk?
        for xpub in xpubs:
            try:
                my_xpub_type = xpub_type(xpub)
            except Exception:
                return True  # maybe old_mpk?
            if my_xpub_type != k_xpub_type:
                return True
        return False

    @staticmethod
    def check_electrum_seed_supported(seed: str) -> None:
        if msg := unsupported_seed_type_message(seed_type(seed)):  # segwit / 2fa
            raise UserFacingException(msg)

    @staticmethod
    def bip39_script_to_xtype(wallet_type: str, script_type: str) -> str:
        # Neurai has no SegWit yet: p2pkh (single-sig) or p2sh (multisig) only
        legacy = 'p2sh' if wallet_type == 'multisig' else 'p2pkh'
        if script_type not in (legacy, 'standard'):
            raise keystore.UnsupportedScriptType(keystore.unsupported_xtype_message(script_type))
        return 'standard'

    def keystore_from_data(self, wallet_type, data):
        if 'seed' in data:
            if data['seed_variant'] == 'electrum':
                self.check_electrum_seed_supported(data['seed'])
                return keystore.from_seed(data['seed'], data['seed_extra_words'], True)
            elif data['seed_variant'] == 'bip39':
                root_seed = keystore.bip39_to_seed(data['seed'], data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                script = self.bip39_script_to_xtype(wallet_type, data['script_type'])
                return keystore.from_bip43_rootseed(root_seed, derivation, xtype=script)
            else:
                raise Exception('Unsupported seed variant %s' % data['seed_variant'])
        elif 'master_key' in data:
            k = keystore.from_master_key(data['master_key'])
            if isinstance(k, keystore.Xpub):
                keystore.check_xtype_supported(xpub_type(k.xpub))
            return k
        else:
            raise Exception('no seed or master_key in data')

    def finished(self, wizard_data):
        self._logger.debug('finished')
        # override

    def create_storage(self, path, data):
        if data['wallet_type'] == '2fa':
            raise UserFacingException(
                _("Two-factor authentication (2FA) wallets are not supported by Electrum-Neurai."))
        assert data['wallet_type'] in ['standard', 'imported', 'multisig']

        if os.path.exists(path):
            raise Exception('file already exists at path')
        storage = WalletStorage(path)

        # TODO: refactor using self.keystore_from_data
        k = None
        if 'keystore_type' not in data:
            assert data['wallet_type'] == 'imported'
            addresses = {}
            if 'private_key_list' in data:
                k = keystore.Imported_KeyStore({})
                keys = keystore.get_private_keys(data['private_key_list'])
                for pk in keys:
                    assert keystore.is_supported_private_key(pk)  # no SegWit keys
                    txin_type, pubkey = k.import_privkey(pk, None)
                    addr = bitcoin.pubkey_to_address(txin_type, pubkey)
                    addresses[addr] = {'type': txin_type, 'pubkey': pubkey}
            elif 'address_list' in data:
                for addr in data['address_list'].split():
                    addresses[addr] = {}
        elif data['keystore_type'] in ['createseed', 'haveseed']:
            if data['seed_type'] in ['old', 'standard']:
                self._logger.debug('creating keystore from electrum seed')
                self.check_electrum_seed_supported(data['seed'])
                k = keystore.from_seed(data['seed'], data['seed_extra_words'], data['wallet_type'] == 'multisig')
            elif data['seed_type'] == 'bip39':
                self._logger.debug('creating keystore from bip39 seed')
                root_seed = keystore.bip39_to_seed(data['seed'], data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                script = self.bip39_script_to_xtype(data['wallet_type'], data['script_type'])
                k = keystore.from_bip43_rootseed(root_seed, derivation, xtype=script)
            elif msg := unsupported_seed_type_message(data['seed_type']):  # segwit, 2fa
                raise UserFacingException(msg)
            else:
                raise Exception('unsupported/unknown seed_type %s' % data['seed_type'])
        elif data['keystore_type'] == 'masterkey':
            k = keystore.from_master_key(data['master_key'])
            if isinstance(k, keystore.Xpub):  # has xpub
                # Neurai has no SegWit yet: no ypub/zpub/Ypub/Zpub
                keystore.check_xtype_supported(xpub_type(k.xpub))
            elif isinstance(k, keystore.Old_KeyStore):
                pass
            else:
                raise Exception(f"unexpected keystore type: {type(keystore)}")
        else:
            raise Exception('unsupported/unknown keystore_type %s' % data['keystore_type'])

        if data['encrypt']:
            if k and k.may_have_password():
                k.update_password(None, data['password'])
            storage.set_password(data['password'], enc_version=StorageEncryptionVersion.USER_PASSWORD)

        db = WalletDB('', storage=storage, manual_upgrades=False)
        db.set_keystore_encryption(bool(data['password']) and data['encrypt'])

        db.put('wallet_type', data['wallet_type'])
        if 'seed_type' in data:
            db.put('seed_type', data['seed_type'])

        if data['wallet_type'] == 'standard':
            db.put('keystore', k.dump())
        elif data['wallet_type'] == 'multisig':
            if not isinstance(k, keystore.Xpub):
                raise Exception(f"unexpected keystore(main) type={type(k)} in multisig. not bip32.")
            k_xpub_type = xpub_type(k.xpub)
            db.put('wallet_type', '%dof%d' % (data['multisig_signatures'],data['multisig_participants']))
            db.put('x1/', k.dump())
            for cosigner in data['multisig_cosigner_data']:
                cosigner_keystore = self.keystore_from_data('multisig', data['multisig_cosigner_data'][cosigner])
                if not isinstance(cosigner_keystore, keystore.Xpub):
                    raise Exception(f"unexpected keystore(cosigner) type={type(cosigner_keystore)} in multisig. not bip32.")
                if k_xpub_type != xpub_type(cosigner_keystore.xpub):
                    raise Exception("multisig wallet needs to have homogeneous xpub types")
                if data['encrypt'] and cosigner_keystore.may_have_password():
                    cosigner_keystore.update_password(None, data['password'])
                db.put(f'x{cosigner}/', cosigner_keystore.dump())
        elif data['wallet_type'] == 'imported':
            if k:
                db.put('keystore', k.dump())
            db.put('addresses', addresses)

        # note: no Lightning keys ('lightning_xprv'): Lightning needs SegWit,
        #       which Neurai does not have yet.

        db.load_plugins()
        db.write()

class ServerConnectWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon):
        AbstractWizard.__init__(self)
        self.navmap = {
            'autoconnect': {
                'next': 'server_config',
                'last': lambda v,d: d['autoconnect']
            },
            'proxy_ask': {
                'next': lambda d: 'proxy_config' if d['want_proxy'] else 'autoconnect'
            },
            'proxy_config': {
                'next': 'autoconnect'
            },
            'server_config': {
                'last': True
            }
        }
        self._daemon = daemon

    def start(self, initial_data=None):
        if initial_data is None:
            initial_data = {}
        self.reset()
        self._current = WizardViewState('proxy_ask', initial_data, {})
        return self._current
