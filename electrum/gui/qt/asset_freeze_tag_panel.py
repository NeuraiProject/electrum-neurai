import enum
import math
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Dict
from functools import lru_cache

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem, QPixmap, QMovie
from PyQt5.QtCore import pyqtSignal, Qt, QItemSelectionModel, QSize
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QSplitter, QScrollArea,
                             QHBoxLayout, QWidget, QFrame, QAbstractItemView,
                             QCheckBox)

from electrum import constants
from electrum.asset import get_error_for_asset_typed, AssetType, generate_freeze_tag
from electrum.bitcoin import base_encode, COIN
from electrum.i18n import _
from electrum.util import format_satoshis_plain, profiler, ipfs_explorer_URL
from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.logging import Logger
from electrum.transaction import PartialTxOutput
from electrum.wallet import get_locktime_for_new_transaction

from .util import HelpLabel, ColorScheme, HelpButton, AutoResizingTextEdit, qt_event_listener, QtEventListener
from .util import QHSeperationLine, read_QIcon, MONOSPACE_FONT, EnterButton, webopen_safe
from .my_treeview import MyTreeView
from .confirm_tx_dialog import ConfirmTxDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from aiohttp import ClientResponse
    from .asset_tab import AssetTab

class AssetFreezeList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()
        FROZEN = enum.auto()

    headers = {
        Columns.ASSET: _('Asset'),
        Columns.FROZEN: _('Frozen'),
    }
    filter_columns = [Columns.ASSET, Columns.FROZEN]

    ROLE_ASSET_STR = Qt.UserRole + 1000
    ROLE_PARENT_IN_MEMPOOL_BOOL = Qt.UserRole + 1001
    ROLE_DATA_DICT = Qt.UserRole + 1002

    key_role = ROLE_ASSET_STR

    def __init__(self, parent: 'ViewFreezePanel'):
        super().__init__(
            main_window=parent.parent.window,
            stretch_columns=[self.Columns.ASSET],
        )
        self.parent = parent
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.last_selected_asset = None
        self.current_assets = []

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                self.parent.update_asset_trigger.emit(None, None, None)
                return
            first_row = min(rows)
            self.last_selected_asset = asset = self.model().index(first_row, self.Columns.ASSET).data(self.ROLE_ASSET_STR)
            in_mempool = self.model().index(first_row, self.Columns.ASSET).data(self.ROLE_PARENT_IN_MEMPOOL_BOOL)
            data = self.model().index(first_row, self.Columns.ASSET).data(self.ROLE_DATA_DICT)
            self.parent.update_asset_trigger.emit(asset, in_mempool, bool(data and data['frozen']))

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        assets = (asset for asset, balance in self.parent.parent.wallet.get_balance(asset_aware=True).items() if asset and 
                  asset[-1] == '!' and sum(balance) > 0 and not get_error_for_asset_typed(asset[:-1], AssetType.ROOT))
        new_assets = sorted([(asset, asset in self.parent.parent.wallet.get_assets_in_mempool()) for asset in assets], key=lambda x: x[0])
        if self.current_assets == new_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (asset, parent_in_mempool) in enumerate(new_assets):
            restricted_asset = f'${asset[:-1]}'
            freeze_data = self.parent.parent.wallet.adb.get_restricted_freeze(restricted_asset)
            labels = [""] * len(self.Columns)
            labels[self.Columns.ASSET] = asset
            labels[self.Columns.FROZEN] = str(freeze_data[0]['frozen'] if freeze_data else False)
            asset_item = [QStandardItem(x) for x in labels]
            icon = read_QIcon('unconfirmed.png') if freeze_data and freeze_data[0]['height'] < 0 else read_QIcon('confirmed.png')
            asset_item[self.Columns.ASSET] = QStandardItem(icon, labels[self.Columns.ASSET])
            self.set_editability(asset_item)
            asset_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            asset_item[self.Columns.ASSET].setData(parent_in_mempool, self.ROLE_PARENT_IN_MEMPOOL_BOOL)
            asset_item[self.Columns.ASSET].setData(freeze_data[0] if freeze_data else None, self.ROLE_DATA_DICT)
            asset_item[self.Columns.ASSET].setFont(QFont(MONOSPACE_FONT))
            asset_item[self.Columns.FROZEN].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, asset_item)
            self.refresh_row(asset, freeze_data, idx)
            if asset == self.last_selected_asset:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_assets = new_assets
        self.filter()

    def refresh_row(self, key: str, data, row: int) -> None:
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        tooltip = 'In the mempool' if data and data[0]['height'] < 0 else 'Confirmed'
        asset_item[self.Columns.ASSET].setToolTip(tooltip)

class FreezePanel(QWidget):
    def __init__(self, parent: 'ViewFreezePanel'):
        QWidget.__init__(self)
        self.parent = parent

        vbox = QVBoxLayout(self)
        self.label = QLabel()
        self.b = EnterButton('', self._create_tx)
        self.b.setMaximumWidth(200)

        vbox.addWidget(self.label)
        vbox.addWidget(self.b)

        self.update()

    def _create_tx(self):
        if not self.current_asset: return
        
        output_amounts = {
            self.current_asset: COIN,
        }

        parent_asset_change_address = self.parent.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.parent.wallet.get_receiving_address() # Fallback
        parent_change_output = PartialTxOutput.from_address_and_value(parent_asset_change_address, COIN, asset=self.current_asset)

        outputs = [parent_change_output]

        def make_tx(fee_est, *, confirmed_only=False):

            tag_vout_script = generate_freeze_tag(f'${self.current_asset[:-1]}', not self.current_frozen)
            tag_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(tag_vout_script), value=0)
            tag_vout_size = len(tag_vout.serialize_to_network())

            def fee_mixin(fee_est):
                def new_fee_estimator(size):
                    # size is virtual bytes
                    # We shouldn't need to worry about vout size varint increasing
                    return fee_est(size + tag_vout_size)
            
                return new_fee_estimator

            try:
                self.parent.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=True)
                assets = {output.asset for output in outputs}.union({None})
                tx = self.parent.parent.wallet.make_unsigned_transaction(
                    coins=[coin for coin in self.parent.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only) if coin.asset in assets],
                    outputs=outputs,
                    fee=fee_est,
                    rbf=False,
                    fee_mixin=fee_mixin
                )
            finally:
                self.parent.parent.wallet.set_reserved_state_of_address(parent_asset_change_address, reserved=False)

            tx.add_outputs([tag_vout], do_sort=False)
            tx.locktime = get_locktime_for_new_transaction(self.parent.parent.network)
            tx.add_info_from_wallet(self.parent.parent.wallet)

            return tx

        conf_dlg = ConfirmTxDialog(window=self.parent.parent.window, make_tx=make_tx, output_value=output_amounts)
        if conf_dlg.not_enough_funds:
            # note: use confirmed_only=False here, regardless of config setting,
            #       as the user needs to get to ConfirmTxDialog to change the config setting
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.parent.parent.get_text_not_enough_funds_mentioning_frozen()
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

                self.b.setEnabled(False)

        self.parent.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)

    def update(self):
        self.label.setText(_('Select a restricted asset to manage the associated restricted asset\'s freeze state.'))
        self.b.setText(_('Freeze Asset'))
        self.b.setEnabled(False)
        self.current_asset = None
        self.current_frozen = False

    def update_info(self, asset: str, mempool: bool, frozen: bool):
        if not asset:
            self.update()
            return
        label = (_('{} is currently frozen.') if frozen else _('{} is not currently frozen.')).format(f'${asset[:-1]}')
        label += ' ' + (_('Allow {} to be transfered again?') if frozen else _('Prevent {} from being transfered?')).format(f'${asset[:-1]}')
        if mempool:
            label += '\n\n' + _('(This parent asset is in the mempool.)')
        self.b.setText(_('Un-Freeze Asset') if frozen else _('Freeze Asset'))
        self.label.setText(label)
        self.b.setEnabled(not mempool)
        self.current_asset = asset
        self.current_frozen = frozen

class ViewFreezePanel(QWidget, Logger):
    update_asset_trigger = pyqtSignal(str, bool, bool)

    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.asset_list = AssetFreezeList(self)
        self.freeze_panel = FreezePanel(self)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self.asset_list)
        vbox.addWidget(self.freeze_panel)

        self.update_asset_trigger.connect(lambda asset, mempool, data: self.freeze_panel.update_info(asset, mempool, data))

    def update(self):
        self.asset_list.update()
        self.freeze_panel.update()
        super().update()
