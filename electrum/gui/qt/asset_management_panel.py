import asyncio
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Callable, Mapping, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QCheckBox, QWidget, QComboBox, QMessageBox

from electrum import constants
from electrum.asset import (get_error_for_asset_typed, AssetType, DEFAULT_ASSET_AMOUNT_MAX, QUALIFIER_ASSET_AMOUNT_MAX, MAX_VERIFIER_STING_LENGTH, generate_create_script, generate_owner_script,
                            MAX_NAME_LENGTH, parse_verifier_string, compress_verifier_string, generate_verifier_tag, generate_reissue_script)
from electrum.bitcoin import base_decode, BaseDecodeError, COIN, is_b58_address, b58_address_to_hash160
from electrum.i18n import _
from electrum.util import get_asyncio_loop, format_satoshis_plain, DECIMAL_POINT, NoQualifiedAddress
from electrum.transaction import PartialTxOutput
from electrum.network import UntrustedServerReturnedError
from electrum.logging import Logger
from electrum.wallet import get_locktime_for_new_transaction
from electrum.boolean_ast_tree import AbstractBooleanASTError

from .amountedit import AmountEdit
from .util import HelpLabel, char_width_in_lineedit, EnterButton, BooleanExprASTTableViewer
from .util import ChoicesLayout, ValidatedDelayedCallbackEditor
from .confirm_tx_dialog import ConfirmTxDialog

if TYPE_CHECKING:
    from .asset_tab import AssetTab


class OnlyNumberAmountEdit(AmountEdit):
    def __init__(self, asset_name: Callable[[], str], divisions: int, max_amount: int, *, parent=None, min_amount=0, callback=None):
        AmountEdit.__init__(self, asset_name, divisions == 0, parent, max_amount=max_amount, min_amount=min_amount, callback=callback)
        self.divisions = divisions

    def decimal_point(self):
        return self.divisions
    
    def max_precision(self):
        return 8

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.setText('')
        return super().numbify()

class AssetAmountEdit(OnlyNumberAmountEdit):
    def _get_amount_from_text(self, text):
        # returns amt in satoshis
        try:
            text = text.replace(DECIMAL_POINT, '.')
            x = Decimal(text)
        except Exception:
            return None
        # scale it to max allowed precision, make it an int
        power = pow(10, self.max_precision())
        max_prec_amount = int(power * x)
        # if the max precision is simply what unit conversion allows, just return
        return max_prec_amount
    
    def _get_text_from_amount(self, amount_sat):
        text = format_satoshis_plain(amount_sat, decimal_point=self.max_precision())
        text = text.replace('.', DECIMAL_POINT)
        return text
    
    def setAmount(self, amount_sat):
        if amount_sat is None:
            self.setText(" ")  # Space forces repaint in case units changed
        else:
            text = self._get_text_from_amount(amount_sat)
            self.setText(text)
        self.repaint()  # macOS hack for #6269

    def numbify(self):
        og_text = self.text().strip()
        super().numbify()
        amount = self.get_amount()
        if amount:
            chunk = Decimal('1' if self.divisions == 0 else f'0.{"".join("0" for i in range(self.divisions - 1))}1') * COIN
            chopped = amount // chunk
            text = self._get_text_from_amount(int(chopped * chunk))
            if og_text[-1] == DECIMAL_POINT:
                text += DECIMAL_POINT
            self.setText(text)
        
class ManageAssetPanel(QWidget, Logger):
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        #grid.setColumnStretch(10, 1)
        #grid.setRowStretch(4, 1)

        self.asset_is_ok = False
        self.associated_data_is_ok = True
        self.address_is_ok = True
        self.asset_combo_is_ok = True
        self.verifier_is_ok = True
        self.combo_assets = set()

        self.asset_selector_combo = QComboBox()
        self.asset_selector_combo.setVisible(False)
        no_resize = self.asset_selector_combo.sizePolicy()
        no_resize.setRetainSizeWhenHidden(True)
        self.asset_selector_combo.setSizePolicy(no_resize)
        self.asset_selector_combo.setStyleSheet("QComboBox { combobox-popup: 0; }")
        self.asset_selector_combo.setMaxVisibleItems(10)
        
        self.burn_amount = 0

        self.asset_selector_combo.currentIndexChanged.connect(self._parent_asset_selector_on_change)
        #self.asset_selector_combo.view().setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        grid.addWidget(self.asset_selector_combo, 0, 2, 1, 9)
        
        self.asset_checker = ValidatedDelayedCallbackEditor(get_asyncio_loop, self._asset_name_fast_fail, 0.5, self._asset_name_delayed_check)

        asset_label = QLabel(_('Name'))
        grid.addWidget(asset_label, 1, 1)
        grid.addWidget(self.asset_checker.line_edit, 1, 2, 1, 9)
        grid.addWidget(self.asset_checker.error_button, 1, 11)

        amount_label = QLabel(_('Amount'))
        self.amount_e = AssetAmountEdit(lambda: self.asset_checker.line_edit.text()[:4], 0, DEFAULT_ASSET_AMOUNT_MAX * COIN, parent=self, min_amount=COIN)
        self.amount_e.setText('1')
        grid.addWidget(amount_label, 2, 1)
        grid.addWidget(self.amount_e, 2, 2)

        divisions_message = _('Asset Divisions') + '\n\n' \
                            + _('Asset divisions are a number from 0 to 8 and denote how many digits past the decimal point can be used. Once an asset is issued, you cannot decrease this number.')
        divisions_label = HelpLabel(_('Divisions'), divisions_message)

        self.divisions_e = OnlyNumberAmountEdit(None, 0, 8, parent=self, callback=self._on_divisions_change)
        divisions_width = char_width_in_lineedit() * 3
        self.divisions_e._width = divisions_width
        self.divisions_e.setMaximumWidth(divisions_width)
        self.divisions_e.setAlignment(Qt.AlignCenter)
        self.divisions_e.setText('0')

        grid.addWidget(divisions_label, 2, 4)
        grid.addWidget(self.divisions_e, 2, 5)

        reissue_label = QLabel(_('Reissuable'))
        self.reissuable = QCheckBox(checked=True)

        grid.addWidget(reissue_label, 2, 7)
        grid.addWidget(self.reissuable, 2, 8)

        associated_data_message = _('Associated Data') + '\n\n' \
                            + _('Data that is associated with an asset. Typically an IPFS hash, but can be a TXID. Leave blank to associate no data.')
        associated_data_label = HelpLabel(_('Associated Data'), associated_data_message)

        def associated_data_fast_fail(input: str):
            self.associated_data_is_ok = False
            self.send_button.setEnabled(False)
            input = input.strip()
            if len(input) == 0:
                self.associated_data_is_ok = True
                self._maybe_enable_pay_button()
                return None
            try:
                if len(input) % 2 == 1 and len(input) > 2 and len(input) < 64:
                    input = input[:-1]
                raw_bytes = bytes.fromhex(input)
                if len(raw_bytes) < 32:
                    return _('Too few bytes for a TXID')
                elif len(raw_bytes) > 32:
                    return _('Too many bytes for a TXID')
                else:
                    self.associated_data_is_ok = True
                    self._maybe_enable_pay_button()
                    return None
            except ValueError:
                try:
                    raw_bytes = base_decode(input, base=58)
                    if len(raw_bytes) < 34:
                        return _('Too few bytes for an IPFS hash')
                    elif len(raw_bytes) > 34:
                        return _('Too many bytes for an IPFS hash')
                    else:
                        self.associated_data_is_ok = True
                        self._maybe_enable_pay_button()
                        return None
                except BaseDecodeError:
                    return _('Failed to parse input')

        grid.addWidget(associated_data_label, 3, 1)
        self.associated_data_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, associated_data_fast_fail, 0, lambda: asyncio.sleep(0))
        grid.addWidget(self.associated_data_e.line_edit, 3, 2, 1, 9)
        grid.addWidget(self.associated_data_e.error_button, 3, 11)

        def verifier_fast_fail(input: str):
            if not input:
                self.payto_label.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)
                self.payto_e.line_edit.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)
                self.payto_e.error_button.setVisible(False)
                if not self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO:
                    self.payto_e.line_edit.setText('')
                self.verifier_is_ok = True
                self.verifier_view.setEnabled(False)
                self.payto_e.validate_text()
                self._maybe_enable_pay_button()
                return None
            self.payto_label.setVisible(True)
            self.payto_e.line_edit.setVisible(True)
            if input[-1] == 'e' and input.lower() == 'true':
                input = 'true'
            else:
                input = input.upper()
            pos = self.verifier_e.line_edit.cursorPosition()
            compressed = compress_verifier_string(input)
            while len(compressed) > MAX_VERIFIER_STING_LENGTH:
                input = input[:-1]
                compressed = compress_verifier_string(input)
            self.verifier_e.line_edit.setText(input)
            self.verifier_e.line_edit.setCursorPosition(pos)
            self.verifier_is_ok = False
            self.verifier_view.setEnabled(False)
            self.send_button.setEnabled(False)
            try:
                node = parse_verifier_string(input)
            except AbstractBooleanASTError as e:
                return e.message
            error = node.iterate_variables_return_first_truthy(lambda name: get_error_for_asset_typed(f'#{name}', AssetType.QUALIFIER))
            if input and error: 
                return error
            if node.is_always_true():
                self.payto_label.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)
                self.payto_e.line_edit.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)
                self.payto_e.error_button.setVisible(False)
                if not self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO:
                    self.payto_e.line_edit.setText('')
                self.verifier_is_ok = True
                self.verifier_view.setEnabled(False)
                self.payto_e.validate_text()
                self._maybe_enable_pay_button()
                return None
            self.payto_e.validate_text()
            return None

        async def validate_qualifiers():
            verifier = self.verifier_e.line_edit.text()
            if not verifier or verifier == 'true':
                return
            node = parse_verifier_string(verifier)
            qualifiers = []
            node.iterate_variables(lambda name: qualifiers.append(f'#{name}'))
            for qualifier in qualifiers:
                if not self.parent.network:
                    self.verifier_e.show_error(_("You are offline."))
                    self.verifier_is_ok = True
                    self._maybe_enable_pay_button()
                    return
                try:
                    raw_metadata = await self.parent.network.get_asset_metadata(qualifier)
                except Exception as e:
                    self.verifier_e.show_error(_("Error getting asset from network") + ":\n" + repr(e))
                    self.verifier_is_ok = True
                    self._maybe_enable_pay_button()
                    return
                if raw_metadata:
                    self.verifier_is_ok = True
                    self.verifier_view.setEnabled(True)
                else:
                    self.verifier_e.show_error(_("Qualifier {} does not exist!").format(qualifier))
                    pass
            if not node.is_always_true():
                try:
                    asset = self.asset_checker.line_edit.text()
                    change_address = self.parent.wallet.get_address_qualified_for_restricted_asset(asset, verifier_string_override=compress_verifier_string(verifier))
                    self.payto_e.line_edit.setText(change_address)
                except NoQualifiedAddress:
                    pass
            self._maybe_enable_pay_button()
            self.verifier_e.error_button.hide()
            return None

        verifier_message = _('Verifier String') + '\n\n' \
                            + _('A boolean string to determine what addresses can recieve this asset. For instance, QUALIFIER would mean only addresses that have been tagged by the #QUALIFIER asset can receive this asset. ! means NOT, & means AND, and | means OR. Leave empty to allow all addresses to receive this asset. This can be changed in a reissue.')
        self.verifier_label = HelpLabel(_('Verifier String'), verifier_message)

        self.verifier_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, verifier_fast_fail, 0.5, validate_qualifiers)

        self.verifier_label.setVisible(False)
        self.verifier_e.line_edit.setVisible(False)

        grid.addWidget(self.verifier_label, 4, 1)
        grid.addWidget(self.verifier_e.line_edit, 4, 2, 1, 7)
        grid.addWidget(self.verifier_e.error_button, 4, 9)

        def show_chart():
            verifier = self.verifier_e.line_edit.text()
            try:
                node = parse_verifier_string(verifier)
            except AbstractBooleanASTError as e:
                return e.message
            d = BooleanExprASTTableViewer(node, self.parent.window)
            d.show()

        self.verifier_view = EnterButton(_('Visualize'), show_chart)
        self.verifier_view.setEnabled(False)
        self.verifier_view.setVisible(False)
        grid.addWidget(self.verifier_view, 4, 10)

        self.payto_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, self._address_fast_fail, 0.5, self._address_delayed_check)

        pay_to_msg = (_("The recipient of the new asset.") + "\n\n"
               + _("If a Bitcoin address is entered, the asset (and any created ownership assets) "
                   "will be sent to this address. "
                   "Leave this empty to send to yourself."))
        self.payto_label = HelpLabel(_('Receiving Address'), pay_to_msg)
        grid.addWidget(self.payto_label, 5, 1)
        grid.addWidget(self.payto_e.line_edit, 5, 2, 1, 9)
        grid.addWidget(self.payto_e.error_button, 5, 11)

        self.payto_label.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)
        self.payto_e.line_edit.setVisible(self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO)

        self.send_button = EnterButton(_("Pay") + f" {self.burn_amount} XNA...", self._create_tx)
        self.send_button.setEnabled(False)
        self.send_button.setMinimumWidth(char_width_in_lineedit() * 16)

        grid.addWidget(self.send_button, 6, 10)

        vbox = QVBoxLayout(self)
        vbox.addLayout(grid)

    def _maybe_enable_pay_button(self):
        self.logger.debug(f'check fields, v={self.verifier_is_ok}, d={self.associated_data_is_ok}, s={self.address_is_ok}, a={self.asset_is_ok}, c={self.asset_combo_is_ok}')
        self.send_button.setEnabled(self.verifier_is_ok and self.associated_data_is_ok and self.address_is_ok and self.asset_is_ok and self.asset_combo_is_ok)

    def _on_divisions_change(self, amount):
        if amount is None:
            return
        assert isinstance(amount, int)
        self.amount_e.divisions = amount
        self.amount_e.is_int = amount == 0
        self.amount_e.min_amount = Decimal('1' if amount == 0 else f'0.{"".join("0" for i in range(amount - 1))}1') * COIN
        self.amount_e.numbify()
        self.amount_e.update()

    def _parent_asset_selector_on_change(self):
        selected_parent_index = self.asset_selector_combo.currentIndex()
        if selected_parent_index <= 0 or len(self.combo_assets) <= (selected_parent_index - 1):
            self.asset_checker.line_edit.setEnabled(False)
            self.asset_checker.line_edit.setText('')
            parent_is_valid = False
        else:
            parent_is_valid = not self.combo_assets[selected_parent_index - 1][1]
        self.asset_combo_is_ok = parent_is_valid
        self._maybe_enable_pay_button()
        
    def _create_tx(self):
        if not self.reissuable.isChecked() and self.parent.window.config.SHOW_REISSUABLE_WARNING:
            cb = QCheckBox(_("Don't show this message again"), checked=False)
            cb_checked = False
            def on_cb(x):
                nonlocal cb_checked
                cb_checked = x == Qt.Checked
            cb.stateChanged.connect(on_cb)
            self.parent.show_warning(_('By making this asset non-reissuable, you will not be able to modify its metadata in the future.'), self,
                                     _('Non-Reissuable'), checkbox=cb)
            if cb_checked:
                self.parent.window.config.SHOW_REISSUABLE_WARNING = False

    def _update_parent_assets(self, _type: AssetType):
        raise NotImplementedError()

    def _get_prefix(self):
        return ''

    async def _asset_name_delayed_check(self):
        raise NotImplementedError()

    def _asset_name_fast_fail(self, asset: str):
        raise NotImplementedError()
    
    def _address_fast_fail(self, input: str):
        raise NotImplementedError()
    
    async def _address_delayed_check(self):
        raise NotImplementedError()

    async def _address_delayed_check_helper(self, address: str):
        if not is_b58_address(address): return
        verifier = self.verifier_e.line_edit.text()
        try:
            node = parse_verifier_string(verifier)
        except AbstractBooleanASTError as e:
            self.payto_e.show_error(_('The verifier string is not valid'))
            return
        vars = set()
        node.iterate_variables(vars.add)
        is_qualified = dict()

        x, h160 = b58_address_to_hash160(address)
        h160_h = h160.hex()
        restricted_asset_name = self.asset_checker.line_edit.text()

        # We are managing the asset -> we have the owner -> we listen for tags for restricted            
        maybe_flag = self.parent.wallet.adb.is_h160_tagged(h160_h, restricted_asset_name)
        if maybe_flag is True:
            self.payto_e.show_error(_('This address is blacklisted from receiving this asset.'))
            return
        
        if self.parent.wallet.adb.db.is_h160_checked(h160_h):
            for var in vars:
                for asset, d in self.parent.wallet.adb.get_tags_for_h160(h160_h, include_mempool=False).items():
                    if (asset == f'#{var}' or asset.startswith(f'#{var}/#')) and d['flag']:
                        is_qualified[var] = True
                        break
                else:
                    is_qualified[var] = False
        else:            
            if not self.parent.network:
                self.payto_e.show_error(_("You are offline."))
                self.address_is_ok = True
                self._maybe_enable_pay_button()
                return
            try:
                result = await self.parent.network.get_tags_for_h160(h160_h)
            except Exception as e:
                self.payto_e.show_error(_("Error getting qualifier status from network") + ":\n" + repr(e))
                self.address_is_ok = True
                self._maybe_enable_pay_button()
                return
            
            for var in vars:
                for asset, d in result.items():
                    if (asset == f'#{var}' or asset.startswith(f'#{var}/#')) and d['flag']:
                        is_qualified[var] = True
                        break
                else:
                    is_qualified[var] = False

        can_receive = node.evaluate(is_qualified)
        if not can_receive:
            self.payto_e.show_error(_('This address cannot receive this asset based on the verifier string (qualifications must exit the mempool)'))
            return

        self.address_is_ok = True
        self._maybe_enable_pay_button()
        return

    def _get_selected_asset(self):
        current_selected_asset_index = self.asset_selector_combo.currentIndex()
        if current_selected_asset_index > 0 and len(self.combo_assets) > (current_selected_asset_index - 1):
            return self.combo_assets[current_selected_asset_index - 1][0]
        return None

    def update(self):
        verifier_string = self.verifier_e.line_edit.text()
        should_show_payto = self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO
        if verifier_string:
            should_show_payto = True
            try:
                node = parse_verifier_string(verifier_string)
                if node.is_always_true():
                    should_show_payto = self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO
            except AbstractBooleanASTError:
                pass
        self.payto_label.setVisible(should_show_payto)
        self.payto_e.line_edit.setVisible(should_show_payto)
        if not self.parent.window.config.SHOW_CREATE_ASSET_PAY_TO:
            self.payto_e.line_edit.setText('')


class CreateAssetPanel(ManageAssetPanel):
    asset_types = (
        ('Main', AssetType.ROOT, constants.net.BURN_ADDRESSES.IssueAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueAssetBurnAmount),
        ('Sub', AssetType.SUB, constants.net.BURN_ADDRESSES.IssueSubAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueSubAssetBurnAmount),
        ('Unique', AssetType.UNIQUE, constants.net.BURN_ADDRESSES.IssueUniqueAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueUniqueAssetBurnAmount),
        ('Message', AssetType.MSG_CHANNEL, constants.net.BURN_ADDRESSES.IssueMsgChannelAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueMsgChannelAssetBurnAmount),
        ('Qualifier', AssetType.QUALIFIER, constants.net.BURN_ADDRESSES.IssueQualifierAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueQualifierAssetBurnAmount),
        ('Sub Qualifier', AssetType.SUB_QUALIFIER, constants.net.BURN_ADDRESSES.IssueSubQualifierAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueSubQualifierAssetBurnAmount),
        ('Restricted', AssetType.RESTRICTED, constants.net.BURN_ADDRESSES.IssueRestrictedAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueRestrictedAssetBurnAmount),
    )

    def __init__(self, parent: 'AssetTab'):
        super().__init__(parent)
        
        self.clayout = ChoicesLayout(_('Asset type'), [x[0] for x in self.asset_types], on_clicked=self._clayout_on_edit, checked_index=0)
        self.burn_address = self.asset_types[self.clayout.selected_index()][2]
        self.burn_amount = self.asset_types[self.clayout.selected_index()][3]

        self.send_grid.addLayout(self.clayout.layout(), 0, 0, 6, 1)
        self._clayout_on_edit(self.clayout)

    def _clayout_on_edit(self, clayout: ChoicesLayout):
        self.burn_address = self.asset_types[clayout.selected_index()][2]
        self.burn_amount = self.asset_types[clayout.selected_index()][3]
        self.send_button.setText(_("Pay") + f" {self.burn_amount} XNA...")

        self.amount_e.setAmount(COIN)
        self.divisions_e.setAmount(0)
        self._on_divisions_change(0)
        self.reissuable.setChecked(True)

        asset_type = self.asset_types[clayout.selected_index()]
        prefix = self._get_prefix(asset_type)
        self.asset_checker.line_edit.setText(prefix)
        if asset_type[1] in (AssetType.ROOT, AssetType.SUB, AssetType.RESTRICTED):
            self.amount_e.max_amount = DEFAULT_ASSET_AMOUNT_MAX * COIN
            self.divisions_e.max_amount = 8
            self.amount_e.setEnabled(True)
            self.divisions_e.setEnabled(True)
            self.reissuable.setEnabled(True)
        elif asset_type[1] in (AssetType.UNIQUE, AssetType.MSG_CHANNEL, AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
            self.amount_e.setEnabled(False)
            self.divisions_e.setEnabled(False)
            self.reissuable.setEnabled(False)
            self.reissuable.setChecked(False)

        if asset_type[1] in (AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
            self.amount_e.setEnabled(True)
            self.amount_e.max_amount = QUALIFIER_ASSET_AMOUNT_MAX * COIN

        if asset_type[1] in (AssetType.MSG_CHANNEL, ):
            self.associated_data_e.line_edit.setText('')
            self.associated_data_e.line_edit.setEnabled(False)
        else:
            self.associated_data_e.line_edit.setEnabled(True)

        if asset_type[1] in (AssetType.RESTRICTED, ):
            self.verifier_view.setVisible(True)
            self.verifier_e.line_edit.setVisible(True)
            self.verifier_label.setVisible(True)
        else:
            self.verifier_view.setVisible(False)
            self.verifier_e.error_button.setVisible(False)
            self.verifier_e.line_edit.setVisible(False)
            self.verifier_label.setVisible(False)
            self.verifier_e.line_edit.setText('')

        self.asset_selector_combo.setVisible(asset_type[1] not in (AssetType.ROOT, AssetType.QUALIFIER))
        self._update_parent_assets(asset_type[1])

        if asset_type[1] in (AssetType.ROOT, AssetType.QUALIFIER):
            self.asset_checker.line_edit.setEnabled(True)
            self.asset_combo_is_ok = True
        else:
            selected_index = self.asset_selector_combo.currentIndex()
            # The asset is valid and is not in the mempool
            self.asset_combo_is_ok = selected_index > 0 and len(self.combo_assets) > (selected_index - 1) and not self.combo_assets[selected_index - 1][1]
            if asset_type[1] == AssetType.RESTRICTED:
                if self.asset_combo_is_ok:
                    # A restricted asset has not already been created
                    self.asset_combo_is_ok = not self.combo_assets[selected_index - 1][2]
                self.asset_checker.line_edit.setEnabled(False)
                if selected_index > 0 and len(self.combo_assets) > selected_index - 1:
                    selected_asset = self.combo_assets[selected_index - 1][0]
                    self.asset_checker.line_edit.setText(f'${selected_asset[:-1]}')
                else:
                    self.asset_checker.line_edit.setText('')
            else:
                self.asset_checker.line_edit.setText('')
                self.asset_checker.line_edit.setEnabled(selected_index > 0)
        self.asset_checker.validate_text()

    async def _asset_name_delayed_check(self):
        asset = self.asset_checker.line_edit.text()
        error = get_error_for_asset_typed(asset, self.asset_types[self.clayout.selected_index()][1])
        if error: return

        if not self.parent.network:
            self.asset_checker.show_error(_("You are offline."))
            self.asset_is_ok = True
            self._maybe_enable_pay_button()
            return
        try:
            raw_metadata = await self.parent.network.get_asset_metadata(asset)
        except Exception as e:
            self.asset_checker.show_error(_("Error getting asset from network") + ":\n" + repr(e))
            self.asset_is_ok = True
            self._maybe_enable_pay_button()
            return
        if raw_metadata:
            # Cannot create
            self.asset_checker.show_error(_("This asset already exists!"))
        else:
            self.asset_is_ok = True
            self._maybe_enable_pay_button()

    def _asset_name_fast_fail(self, asset: str):
        selected_index = self.clayout.selected_index()
        if self.asset_types[selected_index][1] in (AssetType.ROOT, AssetType.SUB, AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
            asset = asset.upper()

        prefix = self._get_prefix(self.asset_types[selected_index][1])
        if asset[:len(prefix)] != prefix:
            asset = prefix + asset[len(prefix):]

        asset = asset[:MAX_NAME_LENGTH-1]

        pos = self.asset_checker.line_edit.cursorPosition()
        self.asset_checker.line_edit.setText(asset)
        self.asset_checker.line_edit.setCursorPosition(max(pos, len(asset)))

        self.amount_e.update()
        # Disable the button no matter what
        self.asset_is_ok = False
        self.send_button.setEnabled(False)
        if asset == self._get_prefix(self.asset_types[selected_index][1]):
            return
        error = get_error_for_asset_typed(asset, self.asset_types[self.clayout.selected_index()][1])
        return error

    def _address_fast_fail(self, input: str):
        self.address_is_ok = False
        self.send_button.setEnabled(False)
        asset_type = self.asset_types[self.clayout.selected_index()]
        if input and not is_b58_address(input): 
            return _('Not a valid base58 address')
        if input:
            _type, h160 = b58_address_to_hash160(input)
            if _type != constants.net.ADDRTYPE_P2PKH and not constants.net.MULTISIG_ASSETS:
                return _('Assets must be sent to a P2PKH address')
        verifier_string = self.verifier_e.line_edit.text()
        if asset_type[1] == AssetType.RESTRICTED and verifier_string:
            try:
                node = parse_verifier_string(verifier_string)
                if not node.is_always_true() and not input:
                    return _('This asset must be sent to a qualified address')
            except AbstractBooleanASTError:
                pass
        self.address_is_ok = True
        self._maybe_enable_pay_button()
        return None

    async def _address_delayed_check(self):
        asset_type = self.asset_types[self.clayout.selected_index()]
        verifier_string = self.verifier_e.line_edit.text()
        if asset_type[1] != AssetType.RESTRICTED:
            return
        elif verifier_string:
            try:
                node = parse_verifier_string(verifier_string)
                if node.is_always_true():
                    return
            except AbstractBooleanASTError:
                return
        address = self.payto_e.line_edit.text()
        await self._address_delayed_check_helper(address)
        
    def _parent_asset_selector_on_change(self):
        super()._parent_asset_selector_on_change()
        selected_parent_index = self.asset_selector_combo.currentIndex()
        selected_asset_type_index = self.clayout.selected_index()
        asset_type = self.asset_types[selected_asset_type_index][1]
        self.asset_checker.line_edit.setEnabled(selected_parent_index > 0 and asset_type != AssetType.RESTRICTED)
        current_text = self.asset_checker.line_edit.text()
        if asset_type == AssetType.ROOT:
            user_text = ''
        elif asset_type == AssetType.SUB:
            split = current_text.split('/')
            if len(split) > 1:
                user_text = split[-1]
            else:
                user_text = ''
        elif asset_type == AssetType.UNIQUE:
            split = current_text.split('#')
            if len(split) > 1:
                user_text = split[-1]
            else:
                user_text = ''
        elif asset_type == AssetType.MSG_CHANNEL:
            split = current_text.split('~')
            if len(split) > 1:
                user_text = split[-1]
            else:
                user_text = ''
        elif asset_type == AssetType.QUALIFIER:
            user_text = current_text[1:]
        elif asset_type == AssetType.SUB_QUALIFIER:
            split = current_text.split('#')
            if len(split) > 1:
                user_text = split[-1]
            else:
                user_text = ''
        else:
            user_text = ''
        prefix = self._get_prefix(asset_type)
        self.asset_checker.line_edit.setText(prefix + user_text)
        self.asset_checker.validate_text()

    def _create_tx(self):
        super()._create_tx()
        output = PartialTxOutput.from_address_and_value(self.burn_address, self.burn_amount * COIN)
        outputs = [output]
        goto_address = self.payto_e.line_edit.text()
        asset = self.asset_checker.line_edit.text()
        amount = self.amount_e.get_amount()
        assert isinstance(amount, int)
        divisions = self.divisions_e.get_amount()
        assert isinstance(divisions, int)
        reissuable = self.reissuable.isChecked()
        associated_data = None
        associated_data_raw = self.associated_data_e.line_edit.text().strip()
        if associated_data_raw:
            try:
                associated_data = b'\x54\x20' + bytes.fromhex(associated_data_raw)
            except ValueError:
                associated_data = base_decode(associated_data_raw, base=58)

        if not goto_address:
            asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
            # Lock for parent asset change
            self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=True)
        else:
            asset_change_address = goto_address

        output_amounts = {
            None: self.burn_amount * COIN,
            asset: amount,
        }

        parent_asset_change_address = None
        selected_asset_type_index = self.clayout.selected_index()
        asset_type = self.asset_types[selected_asset_type_index][1]
        if asset_type not in (AssetType.ROOT, AssetType.QUALIFIER):
            parent_asset = self._get_selected_asset()
            output_amounts[parent_asset] = COIN
            parent_asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
            outputs.append(PartialTxOutput.from_address_and_value(parent_asset_change_address, COIN, asset=parent_asset))

        if not goto_address:
            self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=False)

        if asset_type in (AssetType.ROOT, AssetType.SUB):
            output_amounts[f'{asset}!']: COIN

        def make_tx(fee_est, *, confirmed_only=False):
            appended_vouts = []
            if asset_type == AssetType.RESTRICTED:
                # https://github.com/RavenProject/Neurai/blob/e48d932ec70267a62ec3541bdaf4fe022c149f0e/src/assets/assets.cpp#L4567
                # https://github.com/RavenProject/Neurai/blob/e48d932ec70267a62ec3541bdaf4fe022c149f0e/src/assets/assets.cpp#L901
                # Longest verifier string is 75 de-facto. OP_PUSH used.
                verifier_string = self.verifier_e.line_edit.text()
                if not verifier_string:
                    verifier_string = 'true'
                verifier_script = generate_verifier_tag(compress_verifier_string(verifier_string))
                verifier_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(verifier_script), value=0)
                appended_vouts.append(verifier_vout)

            if asset_type in (AssetType.ROOT, AssetType.SUB):
                owner_script = generate_owner_script(asset_change_address, asset)
                owner_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(owner_script), value=0)
                appended_vouts.append(owner_vout)

            create_script = generate_create_script(asset_change_address, asset, amount, divisions, reissuable, associated_data)
            create_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(create_script), value=0)
            appended_vouts.append(create_vout)

            def fee_mixin(fee_est):
                def new_fee_estimator(size):
                    # size is virtual bytes
                    # We shouldn't need to worry about vout size varint increasing
                    appended_size = sum(len(x.serialize_to_network()) for x in appended_vouts)
                    return fee_est(size + appended_size)
            
                return new_fee_estimator

            try:
                if not goto_address:
                    # Freeze a change address so it is seperate from the xna change
                    self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=True)
                if parent_asset_change_address:
                    self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=True)

                tx = self.parent.wallet.make_unsigned_transaction(
                    coins=self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                    outputs=outputs,
                    fee=fee_est,
                    rbf=False,
                    fee_mixin=fee_mixin
                )
            finally:
                if not goto_address:
                    self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=False)
                if parent_asset_change_address:
                    self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=False)

            tx.add_outputs(appended_vouts, do_sort=False)
            tx.locktime = get_locktime_for_new_transaction(self.parent.network)
            tx.add_info_from_wallet(self.parent.wallet)

            return tx

        conf_dlg = ConfirmTxDialog(window=self.parent.window, make_tx=make_tx, output_value=output_amounts)
        if conf_dlg.not_enough_funds:
            # note: use confirmed_only=False here, regardless of config setting,
            #       as the user needs to get to ConfirmTxDialog to change the config setting
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.parent.window.get_text_not_enough_funds_mentioning_frozen()
                self.parent.show_message(text)
                return
        tx = conf_dlg.run()
        if tx is None:
            # user cancelled
            return
        is_preview = conf_dlg.is_preview
        if is_preview:
            self.parent.window.show_transaction(tx)
            return
        def sign_done(success):
            if success:
                self.parent.window.broadcast_or_show(tx)

                self._clayout_on_edit(self.clayout)

        self.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)
        
    def _update_parent_assets(self, _type: AssetType):
        if _type in (AssetType.SUB, AssetType.UNIQUE, AssetType.MSG_CHANNEL):
            types = [AssetType.ROOT, AssetType.SUB]
        elif _type in (AssetType.SUB_QUALIFIER, ):
            types = [AssetType.QUALIFIER]
        elif _type in (AssetType.RESTRICTED, ):
            types = [AssetType.ROOT]
        else:
            return
        
        balance: Mapping[Optional[str], Tuple[int, int, int]] = self.parent.wallet.get_balance(asset_aware=True)
        # confirmed, unconfirmed, unmatured
        parent_assets = set()
        for asset, amount in balance.items():
            if asset is None: continue
            if sum(amount) == 0: continue
            if asset[-1] == '!':
                parent_asset_name = asset[:-1]
            elif asset[0] == '#':
                parent_asset_name = asset
            else: continue
            if all(get_error_for_asset_typed(parent_asset_name, asset_type) for asset_type in types): continue
            parent_assets.add(asset)

        avaliable_parent_assets = sorted(list((asset, asset in self.parent.wallet.get_assets_in_mempool(), self.parent.wallet.adb.get_asset_metadata(f'${asset[:-1]}') is not None) for asset in parent_assets), key=lambda x: x[0])
        if avaliable_parent_assets == self.combo_assets:
            return
        if not avaliable_parent_assets:
            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems([_('You do not own any compatible assets')])
            self.asset_selector_combo.setCurrentIndex(0)
            self.asset_selector_combo.setEnabled(False)
        else:
            current_selected_asset = None
            current_selected_asset_index = self.asset_selector_combo.currentIndex()
            if current_selected_asset_index > 0 and len(self.combo_assets) > (current_selected_asset_index - 1):
                current_selected_asset = self.combo_assets[current_selected_asset_index - 1][0]
            items = [_('Select an asset')]

            for asset, in_mempool, restricted_asset_exists in avaliable_parent_assets:
                if _type == AssetType.RESTRICTED and restricted_asset_exists:
                    items.append(_('{} (created)').format(asset))
                elif in_mempool:
                    items.append(_('{} (mempool)').format(asset))
                else:
                    items.append(asset)

            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems(items)
            self.asset_selector_combo.model().item(0).setEnabled(False)
            for i, (asset, valid1, valid2) in enumerate(avaliable_parent_assets):
                if valid1 or (_type == AssetType.RESTRICTED and valid2):
                    self.asset_selector_combo.model().item(i+1).setEnabled(False)
                if asset == current_selected_asset:
                    self.asset_selector_combo.setCurrentIndex(i+1)
            self.asset_selector_combo.setEnabled(True)
            
        self.combo_assets = avaliable_parent_assets

    def _get_prefix(self, type_: AssetType):
        if type_ == AssetType.QUALIFIER:
            return '#'
        asset = self._get_selected_asset()
        if asset is None: return ''
        if type_ == AssetType.SUB:
            return f'{asset[:-1]}/'
        elif type_ == AssetType.UNIQUE:
            return f'{asset[:-1]}#'
        elif type_ == AssetType.MSG_CHANNEL:
            return f'{asset[:-1]}~'
        elif type_ == AssetType.SUB_QUALIFIER:
            return f'{asset}/#'
        elif type_ == AssetType.RESTRICTED:
            return f'${asset[:-1]}'
        return ''

    def update(self):
        super().update()
        asset_type = self.asset_types[self.clayout.selected_index()]
        self.logger.info(f'updating parent assets for {asset_type[1]}')
        self._update_parent_assets(asset_type[1])

class ReissueAssetPanel(ManageAssetPanel):
    def __init__(self, parent: 'AssetTab'):
        super().__init__(parent)
        self.burn_address = constants.net.BURN_ADDRESSES.ReissueAssetBurnAddress
        self.burn_amount = constants.net.BURN_AMOUNTS.ReissueAssetBurnAmount
        self.send_button.setText(_("Pay") + f" {self.burn_amount} XNA...")
        self.asset_selector_combo.setVisible(True)
        self.amount_e.min_amount = 0
        self.amount_e.setAmount(0)

    def _on_divisions_change(self, amount):
        # You cannot send divided assets when reissuing
        return

    def _create_tx(self):
        super()._create_tx()
        output = PartialTxOutput.from_address_and_value(self.burn_address, self.burn_amount * COIN)
        outputs = [output]
        goto_address = self.payto_e.line_edit.text()
        asset = self.asset_checker.line_edit.text()
        amount = self.amount_e.get_amount()
        assert isinstance(amount, int)
        divisions = self.divisions_e.get_amount()
        assert isinstance(divisions, int)
        reissuable = self.reissuable.isChecked()
        associated_data = None
        associated_data_raw = self.associated_data_e.line_edit.text().strip()
        if associated_data_raw:
            try:
                associated_data = b'\x54\x20' + bytes.fromhex(associated_data_raw)
            except ValueError:
                associated_data = base_decode(associated_data_raw, base=58)

        if not goto_address:
            asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
            # Lock for parent asset change
            self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=True)
        else:
            asset_change_address = goto_address

        output_amounts = {
            None: self.burn_amount * COIN,
            asset: amount,
        }

        selected_asset = self._get_selected_asset()
        if selected_asset[0] == '$':
            parent_asset = f'{selected_asset[1:]}!'
        else:
            parent_asset = f'{selected_asset}!'
        output_amounts[parent_asset] = COIN
        parent_asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                    self.parent.wallet.get_receiving_address() # Fallback
        outputs.append(PartialTxOutput.from_address_and_value(parent_asset_change_address, COIN, asset=parent_asset))

        if not goto_address:
            self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=False)

        def make_tx(fee_est, *, confirmed_only=False):
            appended_vouts = []
            verifier_string = self.verifier_e.line_edit.text()
            if selected_asset[0] == '$':
                # https://github.com/RavenProject/Neurai/blob/e48d932ec70267a62ec3541bdaf4fe022c149f0e/src/assets/assets.cpp#L4567
                # https://github.com/RavenProject/Neurai/blob/e48d932ec70267a62ec3541bdaf4fe022c149f0e/src/assets/assets.cpp#L901
                # Longest verifier string is 75 de-facto. OP_PUSH used.
                if not verifier_string:
                    verifier_string = 'true'

                original_verifier_string_data = self.parent.wallet.adb.db.get_verified_restricted_verifier(selected_asset)
                original_verifier_string = ''
                if original_verifier_string_data:
                    original_verifier_string = original_verifier_string_data['string']
            
                if verifier_string != original_verifier_string:
                    verifier_script = generate_verifier_tag(compress_verifier_string(verifier_string))
                    verifier_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(verifier_script), value=0)
                    appended_vouts.append(verifier_vout)

            original_metadata = self.parent.wallet.adb.get_asset_metadata(asset)
            create_script = generate_reissue_script(asset_change_address, asset, amount, 0xff if original_metadata and divisions == original_metadata[0].divisions else divisions, reissuable, associated_data)
            create_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(create_script), value=0)
            appended_vouts.append(create_vout)

            def fee_mixin(fee_est):
                def new_fee_estimator(size):
                    # size is virtual bytes
                    # We shouldn't need to worry about vout size varint increasing
                    appended_size = sum(len(x.serialize_to_network()) for x in appended_vouts)
                    return fee_est(size + appended_size)
            
                return new_fee_estimator

            try:
                if not goto_address:
                    # Freeze a change address so it is seperate from the xna change
                    self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=True)
                self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=True)

                tx = self.parent.wallet.make_unsigned_transaction(
                    coins=self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                    outputs=outputs,
                    fee=fee_est,
                    rbf=False,
                    fee_mixin=fee_mixin
                )
            finally:
                if not goto_address:
                    self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=False)
                self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=False)

            tx.add_outputs(appended_vouts, do_sort=False)
            tx.locktime = get_locktime_for_new_transaction(self.parent.network)
            tx.add_info_from_wallet(self.parent.wallet)

            return tx

        conf_dlg = ConfirmTxDialog(window=self.parent.window, make_tx=make_tx, output_value=output_amounts)
        if conf_dlg.not_enough_funds:
            # note: use confirmed_only=False here, regardless of config setting,
            #       as the user needs to get to ConfirmTxDialog to change the config setting
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.parent.window.get_text_not_enough_funds_mentioning_frozen()
                self.parent.show_message(text)
                return
        tx = conf_dlg.run()
        if tx is None:
            # user cancelled
            return
        is_preview = conf_dlg.is_preview
        if is_preview:
            self.parent.window.show_transaction(tx)
            return
        def sign_done(success):
            if success:
                self.parent.window.broadcast_or_show(tx)
                self.asset_selector_combo.setCurrentIndex(0)
                
        self.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)
    

    def _parent_asset_selector_on_change(self):
        super()._parent_asset_selector_on_change()
        asset = self._get_selected_asset()
        if not asset: 
            self.amount_e.setAmount(0)
            self.divisions_e.setAmount(0)
            self.associated_data_e.line_edit.setText('')
            self.reissuable.setChecked(True)
            self.verifier_e.line_edit.setText('')
            self.verifier_e.line_edit.setVisible(False)
            self.payto_e.line_edit.setText('')
            self.payto_e.line_edit.setVisible(False)
            self.verifier_label.setVisible(False)
            self.verifier_view.setVisible(False)
            return
        if asset[0] == '$':
            self.verifier_e.line_edit.setVisible(True)
            self.verifier_label.setVisible(True)
            self.verifier_view.setVisible(True)
            original_verifier_string_data = self.parent.wallet.adb.db.get_verified_restricted_verifier(asset)
            original_verifier_string = ''
            if original_verifier_string_data:
                original_verifier_string = original_verifier_string_data['string']
            self.verifier_e.line_edit.setText(original_verifier_string)
        else:
            self.verifier_e.line_edit.setVisible(False)
            self.verifier_label.setVisible(False)
            self.verifier_view.setVisible(False)
            self.verifier_e.line_edit.setText('')
        self.asset_checker.line_edit.setText(asset)
        asset_metadata_tup = self.parent.wallet.adb.get_asset_metadata(asset)
        if not asset_metadata_tup: return
        asset_metadata, x = asset_metadata_tup
        self.divisions_e.setAmount(asset_metadata.divisions)
        self.divisions_e.min_amount = asset_metadata.divisions
        self.amount_e.divisions = asset_metadata.divisions
        self.amount_e.is_int = asset_metadata.divisions == 0
        self.amount_e.max_amount = DEFAULT_ASSET_AMOUNT_MAX * COIN - asset_metadata.sats_in_circulation
        self.amount_e.numbify()
        self.amount_e.update()
        if asset_metadata.associated_data is None:
            associated_data_string = ''
        elif asset_metadata.associated_data[:2] == b'\x54\x20':
            associated_data_string = asset_metadata.associated_data[2:].hex()
        else:
            associated_data_string = asset_metadata.associated_data_as_ipfs()
        self.associated_data_e.line_edit.setText(associated_data_string)

    def _update_assets_avaliable_to_reissue(self):
        balance: Mapping[Optional[str], Tuple[int, int, int]] = self.parent.wallet.get_balance(asset_aware=True)
        # confirmed, unconfirmed, unmatured
        owner_assets = set()
        for asset, amount in balance.items():
            if asset is None: continue
            if sum(amount) == 0: continue
            if asset[-1] != '!': continue
            owner_assets.add(asset)

        reissuable_assets = list()
        for asset in owner_assets:
            is_parent_in_mempool = asset in self.parent.wallet.get_assets_in_mempool()
            
            main_asset = asset[:-1]
            main_asset_metadata = self.parent.wallet.adb.get_asset_metadata(main_asset)
            if main_asset_metadata and main_asset_metadata[0].reissuable:
                reissuable_assets.append((main_asset, is_parent_in_mempool))

            if get_error_for_asset_typed(main_asset, AssetType.ROOT) is None:
                restricted_asset = f'${main_asset}'
                restricted_asset_metadata = self.parent.wallet.adb.get_asset_metadata(restricted_asset)
                if restricted_asset_metadata and restricted_asset_metadata[0].reissuable:
                    reissuable_assets.append((restricted_asset, is_parent_in_mempool))

        reissuable_assets.sort(key=lambda x: x[0])
        if reissuable_assets == self.combo_assets:
            return
        if not reissuable_assets:
            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems([_('You do not control any reissuable assets')])
            self.asset_selector_combo.setCurrentIndex(0)
            self.asset_selector_combo.setEnabled(False)
        else:
            current_selected_asset = None
            current_selected_asset_index = self.asset_selector_combo.currentIndex()
            if current_selected_asset_index > 0 and len(self.combo_assets) > (current_selected_asset_index - 1):
                current_selected_asset = self.combo_assets[current_selected_asset_index - 1][0]
            items = [_('Select an asset')]

            for asset, in_mempool in reissuable_assets:
                if in_mempool:
                    items.append(_('{} (mempool)').format(asset))
                else:
                    items.append(asset)

            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems(items)
            self.asset_selector_combo.model().item(0).setEnabled(False)
            for i, (asset, valid1) in enumerate(reissuable_assets):
                if valid1:
                    self.asset_selector_combo.model().item(i+1).setEnabled(False)
                if asset == current_selected_asset:
                    self.asset_selector_combo.setCurrentIndex(i+1)
            self.asset_selector_combo.setEnabled(True)

        self.combo_assets = reissuable_assets

    def _asset_name_fast_fail(self, asset: str):
        self.asset_is_ok = bool(asset)
        self._maybe_enable_pay_button()
        return None

    async def _asset_name_delayed_check(self):
        return None

    def _address_fast_fail(self, input: str):
        self.address_is_ok = False
        self.send_button.setEnabled(False)
        selected_asset = self._get_selected_asset()
        if input and not is_b58_address(input):
            return _('Not a valid address')
        if input:
            _type, h160 = b58_address_to_hash160(input)
            if _type != constants.net.ADDRTYPE_P2PKH and not constants.net.MULTISIG_ASSETS:
                return _('Assets must be sent to a P2PKH address')
        verifier_string = self.verifier_e.line_edit.text()
        if selected_asset and selected_asset[0] == '$' and verifier_string:
            try:
                node = parse_verifier_string(verifier_string)
                if not node.is_always_true() and not input:
                    return _('This asset must be sent to a qualified address')
            except AbstractBooleanASTError:
                pass
        self.address_is_ok = True
        self._maybe_enable_pay_button()
        return None

    async def _address_delayed_check(self):
        selected_asset = self._get_selected_asset()
        verifier_string = self.verifier_e.line_edit.text()
        if not selected_asset or selected_asset[0] != '$':
            return
        elif verifier_string:
            try:
                node = parse_verifier_string(verifier_string)
                if node.is_always_true():
                    return
            except AbstractBooleanASTError:
                return
        address = self.payto_e.line_edit.text()
        await self._address_delayed_check_helper(address)

    def update(self):
        super().update()
        self.logger.info(f'updating reissuable assets')
        self._update_assets_avaliable_to_reissue()

