import asyncio
import datetime
import itertools
from typing import TYPE_CHECKING, Mapping, Optional, Tuple

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QWidget, QComboBox, QCalendarWidget
from PyQt5.QtCore import QDate, Qt

from .util import (ValidatedDelayedCallbackEditor, HelpLabel, EnterButton, char_width_in_lineedit, Buttons,
                   OkButton, CancelButton, WindowModalDialog)
from .asset_management_panel import OnlyNumberAmountEdit
from .confirm_tx_dialog import ConfirmTxDialog

from electrum.asset import get_error_for_asset_typed, AssetType, AssetMemo
from electrum.bitcoin import base_decode, BaseDecodeError, COIN
from electrum.i18n import _
from electrum.logging import Logger
from electrum.transaction import PartialTxOutput
from electrum.util import get_asyncio_loop
from electrum.wallet import get_locktime_for_new_transaction

if TYPE_CHECKING:
    from asset_tab import AssetTab

class MakeBroadcastPanel(QWidget, Logger):
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent
        grid = QGridLayout(self)

        self.asset_selector_combo = QComboBox()
        self.asset_selector_combo.setMaxVisibleItems(10)

        def associated_data_fast_fail(input: str):
            self.associated_data_is_ok = False
            self.send_button.setEnabled(False)
            if len(input) == 0:
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

        associated_data_message = _('Associated Data') + '\n\n' \
                            + _('Data that is associated with this broadcast. Typically an IPFS hash, but can be a TXID.')
        associated_data_label = HelpLabel(_('Associated Data'), associated_data_message)
        self.associated_data_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, associated_data_fast_fail, 0, lambda: asyncio.sleep(0))

        timestamp_message = _('Timestamp') + '\n\n' \
                        + _('A timestamp associated with this broadcast. Traditionally used as an expiration timestamp.')
        timestamp_label = HelpLabel(_('Timestamp'), timestamp_message)
        self.timestamp = OnlyNumberAmountEdit(None, 0, int.from_bytes(b'\xff' * 7 + b'\x7f', 'little'), callback=self.set_date)

        self.calendar_button = QPushButton(_('None'))
        self.calendar_button.pressed.connect(self.select_date)

        self.send_button = EnterButton(_('Broadcast'), self._create_tx)
        self.send_button.setEnabled(False)
        self.send_button.setMinimumWidth(char_width_in_lineedit() * 16)


        grid.addWidget(self.asset_selector_combo, 0, 1, 1, 3)
        grid.addWidget(associated_data_label, 1, 0, 1, 1, Qt.AlignRight)
        grid.addWidget(self.associated_data_e.line_edit, 1, 1, 1, 3)
        grid.addWidget(self.associated_data_e.error_button, 1, 4)
        grid.addWidget(timestamp_label, 2, 0, 1, 1, Qt.AlignRight)
        grid.addWidget(self.timestamp, 2, 1)
        grid.addWidget(self.calendar_button, 2, 2)
        grid.addWidget(self.send_button, 2, 3)
        grid.addWidget(QWidget(), 3, 1, 5, 5)

        self.avaliable_assets = []
        self.associated_data_is_ok = False


    def _maybe_enable_pay_button(self):
        self.send_button.setEnabled(self.associated_data_is_ok and bool(self.selected_asset))


    def _create_tx(self):
        output_amounts = {
            self.selected_asset: COIN,
        }

        def make_tx(fee_est, *, confirmed_only=False):
            try:
                asset_coin = next(x for x in self.parent.wallet.get_spendable_coins(nonlocal_only=False, confirmed_only=False) if x.asset == self.selected_asset)
            except StopIteration:
                self.parent.show_warning(f'Could not find coin for {self.selected_asset}')
                return

            assert asset_coin.address

            outputs = [
                PartialTxOutput.from_address_and_value(
                    asset_coin.address, 
                    COIN, 
                    asset=self.selected_asset, 
                    memo=AssetMemo(self.associated_data, self.timestamp.get_amount())
                )
            ]

            coins = [coin for coin in self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only) if not coin.asset]
            coins.append(asset_coin)

            tx = self.parent.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs,
                fee=fee_est,
                rbf=False
            )

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
                self.associated_data_e.line_edit.clear()
                self.timestamp.clear()

        self.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)

    def set_date(self, epoch):
        if not epoch:
            self.calendar_button.setText(_('None'))
        else:
            try:
                d = datetime.datetime.fromtimestamp(epoch)
                self.calendar_button.setText(self.format_date(d))
            except (ValueError, OverflowError, OSError):
                self.calendar_button.setText(_('Timestamp Overflow'))

    def select_date(self):
        d = WindowModalDialog(self, _("Select date"))
        d.setMinimumSize(600, 150)
        d.date = None
        vbox = QVBoxLayout()
        def on_date(date):
            d.date = date
        cal = QCalendarWidget()
        cal.setGridVisible(True)
        cal.clicked[QDate].connect(on_date)
        vbox.addWidget(cal)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        d.setLayout(vbox)
        if d.exec_():
            if d.date is None:
                return None
            date = d.date.toPyDate()
            self.calendar_button.setText(self.format_date(date))
            self.timestamp.setAmount(
                int(datetime.datetime(date.year, date.month, date.day, 0, 0).timestamp()))

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def update(self):        
        balance: Mapping[Optional[str], Tuple[int, int, int]] = self.parent.wallet.get_balance(asset_aware=True)
        avaliable_assets = sorted(asset for asset, b in balance.items() if sum(b) > 0 and asset and 
                                  (get_error_for_asset_typed(asset, AssetType.OWNER) is None or 
                                   get_error_for_asset_typed(asset, AssetType.MSG_CHANNEL) is None))
        if avaliable_assets == self.avaliable_assets:
            return
        
        if not avaliable_assets:
            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems([_('You do not own any compatible assets')])
            self.asset_selector_combo.setCurrentIndex(0)
            self.asset_selector_combo.setEnabled(False)
        else:
            items = [_('Select an asset')]
            items.extend(avaliable_assets)
            self.asset_selector_combo.clear()
            self.asset_selector_combo.addItems(items)
            self.asset_selector_combo.model().item(0).setEnabled(False)
            if self.selected_asset:
                try:
                    i = items.index(self.selected_asset)
                    self.asset_selector_combo.setCurrentIndex(i)
                except ValueError:
                    pass
            self.asset_selector_combo.setEnabled(True)

        self.avaliable_assets = avaliable_assets
        super().update()


    @property
    def selected_asset(self):
        current_selected_asset = None
        current_selected_asset_index = self.asset_selector_combo.currentIndex()
        if current_selected_asset_index > 0 and len(self.avaliable_assets) > (current_selected_asset_index - 1):
            current_selected_asset = self.avaliable_assets[current_selected_asset_index - 1]
        return current_selected_asset

    @property
    def associated_data(self):
        raw = self.associated_data_e.line_edit.text()
        if len(raw) == 64:
            return f'5420{raw}'
        return raw
