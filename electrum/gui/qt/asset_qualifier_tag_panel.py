import asyncio
import enum
import math
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import pyqtSignal, Qt, QItemSelectionModel
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QSplitter, QScrollArea,
                             QHBoxLayout, QWidget, QFrame, QAbstractItemView,
                             QTextEdit, QGridLayout, QCheckBox)

from electrum import constants
from electrum.asset import get_error_for_asset_typed, AssetType, generate_null_tag
from electrum.bitcoin import hash160_to_b58_address, is_b58_address, b58_address_to_hash160, COIN
from electrum.i18n import _
from electrum.util import profiler, get_asyncio_loop, SearchableListGrouping
from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.logging import Logger
from electrum.transaction import PartialTxOutput
from electrum.wallet import get_locktime_for_new_transaction

from .util import HelpLabel, HelpButton, ValidatedDelayedCallbackEditor, char_width_in_lineedit
from .util import QHSeperationLine, read_QIcon, MONOSPACE_FONT, font_height, EnterButton
from .my_treeview import MyTreeView
from .confirm_tx_dialog import ConfirmTxDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from aiohttp import ClientResponse
    from .asset_tab import AssetTab

class TaggedAddressList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        ADDRESS = enum.auto()
        TAGGED = enum.auto()

    headers = {
        Columns.ADDRESS: _('Address'),
        Columns.TAGGED: _('Flag')
    }

    filter_columns = [Columns.ADDRESS, Columns.TAGGED]

    ROLE_ADDRESS_STR = Qt.UserRole + 1000
    ROLE_TAG_BOOL = Qt.UserRole + 1001
    key_role = ROLE_ADDRESS_STR

    def __init__(self, parent: 'QualifierAssetPanel'):
        super().__init__(
            main_window=parent.parent.window,
            stretch_columns=[self.Columns.ADDRESS]
        )
        self.parent = parent
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.last_selected_address = None
        self.current_h160s = None
        self.taggee = None

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                self.parent.update_address_trigger.emit((None, True))
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.ADDRESS)
            self.last_selected_address = address = m.data(self.ROLE_ADDRESS_STR)
            flag = m.data(self.ROLE_TAG_BOOL)
            self.parent.update_address_trigger.emit((address, flag))

        self.selectionModel().selectionChanged.connect(selectionChange)

    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        new_h160s = self.wallet.adb.get_tags_for_qualifier(self.taggee) if self.taggee else dict()
        if self.current_h160s == new_h160s:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (h160, data) in enumerate(sorted(new_h160s.items(), key=lambda x: x[0])):
            labels = [""] * len(self.Columns)

            addr = hash160_to_b58_address(bytes.fromhex(h160), constants.net.ADDRTYPE_P2PKH)
            labels[self.Columns.ADDRESS] = addr
            labels[self.Columns.TAGGED] = str(data['flag'])
            row_item = [QStandardItem(x) for x in labels]
            icon = read_QIcon('unconfirmed.png') if data['height'] < 0 else read_QIcon('confirmed.png')
            row_item[self.Columns.ADDRESS] = QStandardItem(icon, labels[self.Columns.ADDRESS])
            self.set_editability(row_item)
            row_item[self.Columns.ADDRESS].setData(addr, self.ROLE_ADDRESS_STR)
            row_item[self.Columns.ADDRESS].setData(data['flag'], self.ROLE_TAG_BOOL)
            row_item[self.Columns.ADDRESS].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, row_item)
            self.refresh_row(h160, data, idx)
            if addr == self.last_selected_address:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_h160s = new_h160s
        self.filter()

    def refresh_row(self, key: str, data, row: int) -> None:
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        
        tooltip = 'In the mempool' if data['height'] < 0 else 'Confirmed'

        asset_item[self.Columns.ADDRESS].setToolTip(tooltip)

class SmallAssetList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()

    headers = {
        Columns.ASSET: _('Asset'),
    }
    filter_columns = [Columns.ASSET]

    ROLE_ASSET_STR = Qt.UserRole + 1000
    ROLE_IN_MEMPOOL_BOOL = Qt.UserRole + 1001
    key_role = ROLE_ASSET_STR

    def __init__(self, parent: 'QualifierAssetPanel', filter, id):
        super().__init__(
            main_window=parent.parent.window,
            stretch_columns=[self.Columns.ASSET],
        )
        self.parent = parent
        self.wallet = self.main_window.wallet
        self.filter_asset = filter
        self.id = id
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.last_selected_asset = None
        self.current_assets = []

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                self.parent.update_asset_trigger.emit((self.id, None, True))
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.ASSET)
            self.last_selected_asset = asset = m.data(self.ROLE_ASSET_STR)
            in_mempool = m.data(self.ROLE_IN_MEMPOOL_BOOL)
            self.parent.update_asset_trigger.emit((self.id, asset, in_mempool))
            self.parent.update_address_trigger.emit((None, True))

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        new_assets = [(asset, asset in self.wallet.get_assets_in_mempool()) for asset, (c, u, x) in self.wallet.get_balance(asset_aware=True).items() if self.filter_asset(asset) and (c + u + x) > 0]
        if self.current_assets == new_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (asset, data) in enumerate(new_assets):
            labels = [""] * len(self.Columns)
            labels[self.Columns.ASSET] = asset
            asset_item = [QStandardItem(x) for x in labels]
            self.set_editability(asset_item)
            asset_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            asset_item[self.Columns.ASSET].setData(data, self.ROLE_IN_MEMPOOL_BOOL)

            asset_item[self.Columns.ASSET].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, asset_item)
            self.refresh_row(asset, data, idx)
            if asset == self.last_selected_asset:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_assets = new_assets
        self.filter()

    def refresh_row(self, key, data, row):
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        
        color = self._default_bg_brush

        for col in asset_item:
            col.setBackground(color)
            #col.setToolTip(tooltip)

class AssetStack(QWidget):
    def __init__(self, parent: 'QualifierAssetPanel', qual_id, res_id):
        QWidget.__init__(self)
        self.qualifiers = SmallAssetList(parent, lambda x: x and x[0] == '#', qual_id)
        self.restricted = SmallAssetList(parent, lambda x: x and x[-1] == '!' and get_error_for_asset_typed(x[:-1], AssetType.ROOT) is None, res_id)
        view = QVBoxLayout(self)
        view.addWidget(QLabel(_('Qualifier Tag Choices')))
        view.addWidget(self.qualifiers)
        view.addWidget(QLabel(_('Restricted Tag Choices')))
        view.addWidget(self.restricted)
        
        self.qualifiers.selectionModel().selectionChanged.connect(lambda new, old: self.restricted.clearSelection() if new else None)
        self.restricted.selectionModel().selectionChanged.connect(lambda new, old: self.qualifiers.clearSelection() if new else None)

    def update(self):
        self.qualifiers.update()
        self.restricted.update()


class TagAddress(QWidget):
    def __init__(self, parent: 'QualifierAssetPanel'):
        QWidget.__init__(self)
        self.parent = parent
        
        grid = QGridLayout(self)
        
        self.label = QLabel(_('Create New Address Tag'))
        grid.addWidget(self.label, 0, 0, 1, 5)
        
        def address_fast_fail(input: str):
            self.send_button.setEnabled(False)
            if not input:
                return _('An address must be entered')
            if not is_b58_address(input): 
                return _('Not a valid address')
            _type, h160 = b58_address_to_hash160(input)
            if _type != constants.net.ADDRTYPE_P2PKH and not constants.net.MULTISIG_ASSETS:
                return _('Must be a P2PKH address')
            self._address_is_ok = True
            self.send_button.setEnabled(not self.selected_asset_in_mempool and self._address_is_ok)
            return None

        address_msg = (_("The address to target.") + "\n\n"
               + _('This is the address that gets tagged by the asset.'))
        address_label = HelpLabel(_('Address to Tag'), address_msg)
        self.address_validator = ValidatedDelayedCallbackEditor(get_asyncio_loop, address_fast_fail, 0, lambda: asyncio.sleep(0))

        grid.addWidget(address_label, 1, 0)
        grid.addWidget(self.address_validator.line_edit, 1, 1, 1, 3)
        grid.addWidget(self.address_validator.error_button, 1, 4)

        should_tag_cb_msg = _('A checked box indicates a flag of "true" and an unchecked box indicates a flag of "false"')
        should_tag_cb_label = HelpLabel(_('New Flag State'), should_tag_cb_msg)
        self.should_tag_cb = QCheckBox(checked=False)
        grid.addWidget(should_tag_cb_label, 2, 0)
        grid.addWidget(self.should_tag_cb, 2, 1)

        self.in_mempool_label = QLabel(_('In Mempool'))
        self.in_mempool_label.setVisible(False)
        grid.addWidget(self.in_mempool_label, 2, 2)

        self.send_button = EnterButton(_("Pay") + f" {constants.net.BURN_AMOUNTS.AddNullQualifierTagBurnAmount} RVN...", self.create_tag)
        self.send_button.setEnabled(False)
        self.send_button.setMinimumWidth(char_width_in_lineedit() * 16)
        grid.addWidget(self.send_button, 2, 3)

        help_button = HelpButton(_('Address Tagging:') + '\n\n' + 
                                _('Address tags are used in conjuction with verifier strings to determine what addresses can and cannot receive a restricted asset. If an address does not '
                                  'explicitly have a tag, its flag value is "false".') + '\n\n' +
                                _('With an ownership asset or qualifier asset, one can "tag" an address with a "flag" that is a boolean value; "true" or "false". '
                                  'Tagging with a qualifier asset and an ownership asset have different meanings.') + '\n\n' +
                                _('When tagging with an ownership asset, a flag of "true" means that this address may not recieve the associated restricted asset (which may not have been created yet) no '
                                  'matter what. A flag of "false" returns the address to the default check for restricted assets as outlined below:') + '\n\n' +
                                _('When tagging with a qualifier, the boolean flag is associated with the address for the qualifier. Sub-qualifier tags fill the same spot as their parent qualifier in the verifier string. '
                                  'If any of the qualifiers or sub-qualifiers have a "true" tag for the address, "true" will be used in the verifier string. When sending a restricted asset, '
                                  'it can be sent to an address if the result of the verifier string evaluates to "true" when the variables are replaced by the associated flags associated with the address.') + '\n\n' +
                                _('Example: $RESTRICTED has a verifier string of "QUALIFIER1&QUALIFIER2".') + '\n\n' +
                                _('Address A has been tagged by #QUALIFIER1 and #QUALIFIER2 with a flag of "true" for both; Address A can receive $RESTRICTED.') + '\n\n' +
                                _('Address B has only been tagged by #QUALIFIER1 with a flag of "true". Because tag values default to "false", the verifier string check becomes "true" & "false" which equates to "false"; '
                                  'Address B cannot recieve $RESTRICTED.') + '\n\n' +
                                _('Address C has been tagged by #QUALIFIER1 and #QUALIFIER2 with a flag of "true" for both. Address C has also been tagged by RESTRICTED! with a flag of "true"; '
                                  'Address C cannot receive $RESTRICTED.'), wide=True)
        grid.addWidget(help_button, 2, 4)
        
        self.setEnabled(False, True)
        self.selected_asset = None
        self.selected_asset_in_mempool = False
        self._address_is_ok = False

    def create_tag(self):
        if not self.selected_asset: return
        address = self.address_validator.line_edit.text()
        if not is_b58_address(address): return
        _type, h160 = b58_address_to_hash160(address)
        flag = self.should_tag_cb.isChecked()

        if self.selected_asset[0] == '#':
            tagger = self.selected_asset
        elif self.selected_asset[-1] == '!':
            tagger = f'${self.selected_asset[:-1]}'

        burnAmount = math.floor(constants.net.BURN_AMOUNTS.AddNullQualifierTagBurnAmount * COIN)
        burnAddress = constants.net.BURN_ADDRESSES.AddNullQualifierTagBurnAddress

        output_amounts = {
            None: burnAmount,
            self.selected_asset: COIN,
        }

        parent_asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
        parent_change_output = PartialTxOutput.from_address_and_value(parent_asset_change_address, COIN, asset=self.selected_asset)

        burn_output = PartialTxOutput.from_address_and_value(burnAddress, burnAmount)
        outputs = [burn_output, parent_change_output]

        def make_tx(fee_est, *, confirmed_only=False):
            tag_vout_script = generate_null_tag(tagger, h160.hex(), flag)
            tag_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(tag_vout_script), value=0)
            tag_vout_size = len(tag_vout.serialize_to_network())

            def fee_mixin(fee_est):
                def new_fee_estimator(size):
                    # size is virtual bytes
                    # We shouldn't need to worry about vout size varint increasing
                    return fee_est(size + tag_vout_size)
            
                return new_fee_estimator

            try:
                self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=True)

                tx = self.parent.wallet.make_unsigned_transaction(
                    coins=self.parent.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                    outputs=outputs,
                    fee=fee_est,
                    rbf=False,
                    fee_mixin=fee_mixin
                )
            finally:
                self.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=False)

            tx.add_outputs([tag_vout], do_sort=False)
            tx.locktime = get_locktime_for_new_transaction(self.parent.parent.network)
            tx.add_info_from_wallet(self.parent.wallet)

            return tx

        conf_dlg = ConfirmTxDialog(window=self.parent.parent.window, make_tx=make_tx, output_value=output_amounts)
        if conf_dlg.not_enough_funds:
            # note: use confirmed_only=False here, regardless of config setting,
            #       as the user needs to get to ConfirmTxDialog to change the config setting
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.parent.parent.window.get_text_not_enough_funds_mentioning_frozen()
                self.parent.parent.show_message(text)
                return
        tx = conf_dlg.run()
        if tx is None:
            # user cancelled
            return
        is_preview = conf_dlg.is_preview
        if is_preview:
            self.parent.parent.window.show_transaction(tx)
            return
        def sign_done(success):
            if success:
                self.parent.parent.window.broadcast_or_show(tx)

                self.parent.update_address_trigger.emit((None, False))
                self.parent.set_qualifier.list.last_selected_address = None
                self.parent.set_qualifier.list.current_h160s = None
                self.parent.set_qualifier.list.update()
                
        self.parent.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)

    def setEnabled(self, asset, in_mempool):
        if not asset:
            self.address_validator.line_edit.setText('')
            self.address_validator.line_edit.setEnabled(False)
            self.should_tag_cb.setChecked(False)
            self.should_tag_cb.setEnabled(False)
            asset_selection_message = _('An asset must be selected')
            self.address_validator.error_button.help_text = asset_selection_message
            self.address_validator.error_button.setToolTip(asset_selection_message)
            self.address_validator.error_button.setVisible(True)
            self.send_button.setEnabled(False)
            self.label.setText(_('Create New Address Tag'))
        else:
            self.address_validator.line_edit.setEnabled(True)
            self.address_validator.error_button.setVisible(False)
            self.address_validator.error_button.setToolTip('')
            self.should_tag_cb.setEnabled(True)
            if asset[-1] == '!':
                tagger = f'${asset[:-1]}'
            elif asset[0] == '#':
                tagger = asset
            self.label.setText(_('Create Tag For {}').format(tagger))
            self.selected_asset = asset
            self.selected_asset_in_mempool = in_mempool
            self.send_button.setEnabled(not self.selected_asset_in_mempool and self._address_is_ok)
            self.in_mempool_label.setVisible(self.selected_asset_in_mempool)

class TaggingStack(QWidget):    
    def __init__(self, parent, qual_id, res_id):
        QWidget.__init__(self)

        self.parent = parent
        self.qual_id = qual_id
        self.res_id = res_id

        self.info_label = QLabel(_('Select an asset to view its tags'))
        self.list = TaggedAddressList(parent)
        self.tag_address = TagAddress(parent)
        view = QVBoxLayout(self)
        view.addWidget(self.info_label)
        view.addWidget(self.list)
        view.addWidget(QHSeperationLine())
        view.addWidget(self.tag_address)
        
        self.qual_is_none = False
        self.res_is_none = False

    def update_address_selection(self, address, is_tagged):
        if address is None:
            self.tag_address.address_validator.line_edit.setText('')
            self.tag_address.should_tag_cb.setChecked(False)
        else:
            self.tag_address.address_validator.line_edit.setText(address)
            self.tag_address.should_tag_cb.setChecked(is_tagged)

    def update_stack(self, id, asset, in_mempool):
        if asset is None:
            if id == self.qual_id:
                self.qual_is_none = True
                if self.res_is_none:
                    self.list.taggee = asset
                    self.list.update()
                    self.info_label.setText(_('Select an asset to view its tags'))
                    self.tag_address.setEnabled(False, True)
            else:
                self.res_is_none = True
                if self.qual_is_none:
                    self.list.taggee = asset
                    self.list.update()
                    self.info_label.setText(_('Select an asset to view its tags'))
                    self.tag_address.setEnabled(False, True)
            return
        if id == self.qual_id:
            self.qual_is_none = False
        else:
            self.res_is_none = False
        if asset[0] == '#':
            tagger = asset
        elif asset[-1] == '!':
            tagger = f'${asset[:-1]}'
        self.info_label.setText(_('Tags for {}').format(tagger))
        self.tag_address.setEnabled(asset, in_mempool)
        self.list.taggee = tagger
        self.list.update()

    def update(self):
        self.list.update()
        super().update()

class QualifierAssetPanel(QSplitter, Logger):
    update_asset_trigger = pyqtSignal(object)
    update_address_trigger = pyqtSignal(object)

    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent
        self.wallet = parent.wallet

        self.asset_list = AssetStack(self, 'q', 'r')
        self.set_qualifier = TaggingStack(self, 'q', 'r')

        self.asset_list.setMinimumWidth(250)
        self.set_qualifier.setMinimumWidth(420)

        self.setChildrenCollapsible(False)
        self.addWidget(self.asset_list)
        self.addWidget(self.set_qualifier)

        self.setStretchFactor(0, 0)
        self.setStretchFactor(1, 1)

        self.setSizes([320, 350])

        self.update_asset_trigger.connect(lambda args: self.set_qualifier.update_stack(*args))
        self.update_address_trigger.connect(lambda args: self.set_qualifier.update_address_selection(*args))

        self.searchable_list_grouping = SearchableListGrouping(self.asset_list.qualifiers, 
                                                               self.asset_list.restricted, 
                                                               self.set_qualifier.list)

    def update(self):
        self.asset_list.update()
        self.set_qualifier.update()
        super().update()

    