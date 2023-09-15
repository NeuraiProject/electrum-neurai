#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import enum

from typing import TYPE_CHECKING

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QTabWidget, QWidget, QAbstractItemView

from electrum.bitcoin import b58_address_to_hash160, is_b58_address
from electrum.i18n import _
from electrum.util import profiler

from .util import (WindowModalDialog, ButtonsLineEdit, ShowQRLineEdit, ColorScheme, Buttons, 
                   CloseButton, read_QIcon, MONOSPACE_FONT)
from .history_list import HistoryList, HistoryModel
from .my_treeview import MyTreeView
from .qrtextedit import ShowQRTextEdit

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class AddressHistoryModel(HistoryModel):
    def __init__(self, window: 'ElectrumWindow', address):
        super().__init__(window)
        self.address = address

    def get_domain(self):
        return [self.address]

    def should_include_lightning_payments(self) -> bool:
        return False


class TaggedAddressList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()
        TAGGED = enum.auto()

    headers = {
        Columns.ASSET: _('Asset'),
        Columns.TAGGED: _('Flag')
    }

    filter_columns = [Columns.ASSET, Columns.TAGGED]

    ROLE_ASSET_STR = Qt.UserRole + 1000
    ROLE_TAG_BOOL = Qt.UserRole + 1001
    key_role = ROLE_ASSET_STR

    def __init__(self, electrum_window: 'ElectrumWindow', h160: str):
        super().__init__(
            main_window=electrum_window,
            stretch_columns=[self.Columns.ASSET]
        )
        self.electrum_window = electrum_window
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.last_selected_asset = None
        self.current_assets = None
        self.h160 = h160

    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        new_assets = self.wallet.adb.get_tags_for_h160(self.h160)
        if self.current_assets == new_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (asset, data) in enumerate(sorted(new_assets.items(), key=lambda x: x[0])):
            labels = [""] * len(self.Columns)

            labels[self.Columns.ASSET] = asset
            labels[self.Columns.TAGGED] = str(data['flag'])
            row_item = [QStandardItem(x) for x in labels]
            icon = read_QIcon('unconfirmed.png') if data['height'] < 0 else read_QIcon('confirmed.png')
            row_item[self.Columns.ASSET] = QStandardItem(icon, labels[self.Columns.ASSET])
            self.set_editability(row_item)
            row_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            row_item[self.Columns.ASSET].setData(data['flag'], self.ROLE_TAG_BOOL)
            row_item[self.Columns.ASSET].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, row_item)
            self.refresh_row(data, idx)
        self.current_assets = new_assets
        self.filter()

    def refresh_row(self, data, row: int) -> None:
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        
        tooltip = 'In the mempool' if data['height'] < 0 else 'Confirmed'

        asset_item[self.Columns.ASSET].setToolTip(tooltip)


class AddressDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', address: str, *, parent=None):
        if parent is None:
            parent = window
        WindowModalDialog.__init__(self, parent, _("Address"))
        self.address = address
        self.window = window
        self.config = window.config
        self.wallet = window.wallet
        self.app = window.app
        self.saved = True

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address") + ":"))
        self.addr_e = ShowQRLineEdit(self.address, self.config, title=_("Address"))
        vbox.addWidget(self.addr_e)

        try:
            pubkeys = self.wallet.get_public_keys(address)
        except BaseException as e:
            pubkeys = None
        if pubkeys:
            vbox.addWidget(QLabel(_("Public keys") + ':'))
            for pubkey in pubkeys:
                pubkey_e = ShowQRLineEdit(pubkey, self.config, title=_("Public Key"))
                vbox.addWidget(pubkey_e)

        redeem_script = self.wallet.get_redeem_script(address)
        if redeem_script:
            vbox.addWidget(QLabel(_("Redeem Script") + ':'))
            redeem_e = ShowQRTextEdit(text=redeem_script, config=self.config)
            redeem_e.addCopyButton()
            vbox.addWidget(redeem_e)

        witness_script = self.wallet.get_witness_script(address)
        if witness_script:
            vbox.addWidget(QLabel(_("Witness Script") + ':'))
            witness_e = ShowQRTextEdit(text=witness_script, config=self.config)
            witness_e.addCopyButton()
            vbox.addWidget(witness_e)

        address_path_str = self.wallet.get_address_path_str(address)
        if address_path_str:
            vbox.addWidget(QLabel(_("Derivation path") + ':'))
            der_path_e = ButtonsLineEdit(address_path_str)
            der_path_e.addCopyButton()
            der_path_e.setReadOnly(True)
            vbox.addWidget(der_path_e)

        addr_hist_model = AddressHistoryModel(self.window, self.address)
        self.hw = HistoryList(self.window, addr_hist_model)
        self.hw.num_tx_label = QLabel('')
        addr_hist_model.set_view(self.hw)

        if is_b58_address(self.address):
            x, h160 = b58_address_to_hash160(self.address)
            h160_h = h160.hex()

            if self.wallet.adb.get_tags_for_h160(h160_h):
                tabs = QTabWidget()

                vbox_history = QVBoxLayout()
                vbox_history.addWidget(self.hw.num_tx_label)
                vbox_history.addWidget(self.hw)
                history_widget = QWidget()
                history_widget.setLayout(vbox_history)

                tags_widget = TaggedAddressList(self.window, h160_h)
                tags_widget.update()

                tabs.addTab(history_widget, read_QIcon('tab_history.png'), _('History'))
                tabs.addTab(tags_widget, read_QIcon('tag.png'), _('Tags'))

                vbox.addWidget(tabs)
            else:
                vbox.addWidget(self.hw.num_tx_label)
                vbox.addWidget(self.hw)
        else:
            vbox.addWidget(self.hw.num_tx_label)
            vbox.addWidget(self.hw)

        vbox.addLayout(Buttons(CloseButton(self)))
        self.format_amount = self.window.format_amount
        addr_hist_model.refresh('address dialog constructor')

    def show_qr(self):
        text = self.address
        try:
            self.window.show_qrcode(text, 'Address', parent=self)
        except Exception as e:
            self.show_message(repr(e))
