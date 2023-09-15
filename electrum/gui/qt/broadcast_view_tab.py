import enum
from typing import TYPE_CHECKING

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, pyqtSignal, QItemSelectionModel, QPoint
from PyQt5.QtWidgets import (QAbstractItemView, QWidget, QHBoxLayout, QVBoxLayout, QToolButton, QMenu,
                             QLineEdit, QScrollArea, QLabel)

from .my_treeview import MyTreeView, MyMenu
from .util import IPFSViewer, read_QIcon, EnterButton, MessageBoxMixin, QHSeperationLine, AutoResizingTextEdit

from electrum.asset import get_error_for_asset_typed, AssetType
from electrum.bitcoin import base_decode
from electrum.i18n import _
from electrum.logging import Logger
from electrum.util import profiler, SearchableListGrouping

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class BroadcastAssetList(MyTreeView):

    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()

    headers = {
        Columns.ASSET: _('Asset')
    }

    filter_columns = [Columns.ASSET]

    ROLE_ASSET_STR = Qt.UserRole + 1001
    key_role = ROLE_ASSET_STR

    def __init__(self, parent: 'ViewBroadcastTab', main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_columns=[self.Columns.ASSET]
        )
        self.parent = parent
        self.wallet = main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.current_assets = []
        self.last_selected_asset = None

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                parent.update_asset_trigger.emit(None)
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.ASSET)
            self.last_selected_asset = asset = m.data(self.ROLE_ASSET_STR)
            parent.update_asset_trigger.emit(asset)

        self.selectionModel().selectionChanged.connect(selectionChange)
    

    @profiler(min_threshold=0.05)
    def update(self):
        assets = self.wallet.adb.get_broadcasts_to_watch()
        if assets == self.current_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, asset in enumerate(assets):
            labels = [""] * len(self.Columns)
            labels[self.Columns.ASSET] = asset
            row_item = [QStandardItem(x) for x in labels]
            row_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            self.model().insertRow(idx, row_item)
            self.refresh_row(asset, idx)
            if asset == self.last_selected_asset:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_assets = assets
        self.filter()


    def refresh_row(self, key: str, row: int) -> None:
        assert row is not None
        row_item = [self.std_model.item(row, col) for col in self.Columns]
        row_item[self.Columns.ASSET].setToolTip(key)


    def create_menu(self, position: QPoint):
        selected = self.selected_in_column(self.Columns.ASSET)
        if not selected:
            return
        multi_select = len(selected) > 1
        assets = [self.item_from_index(item).text() for item in selected]
        menu = QMenu()
        
        def remove_and_refresh(assets):
            for asset in assets:
                self.main_window.wallet.adb.remove_broadcast_to_watch(asset)
            self.parent.update_asset_trigger.emit(None)
            self.parent.update_associated_data_trigger.emit(None, None, None)
            self.update()

        if not multi_select:
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            item = self.item_from_index(idx)
            if not item:
                return
            asset = assets[0]
            menu.addAction(_('Stop Watching Asset'), lambda: remove_and_refresh([asset]))
        else:
            menu.addAction(_('Stop Watching Assets'), lambda: remove_and_refresh(assets))

        menu.exec_(self.viewport().mapToGlobal(position))


class BroadcastList(MyTreeView):
    
    class Columns(MyTreeView.BaseColumnsEnum):
        HEIGHT = enum.auto()
        DATA = enum.auto()
        TIMESTAMP = enum.auto()

    headers = {
        Columns.HEIGHT: _('Height'),
        Columns.DATA: _('Message'),
        Columns.TIMESTAMP: _('Timestamp')
    }

    filter_columns = [Columns.HEIGHT, Columns.DATA, Columns.TIMESTAMP]

    ROLE_ID_STR = Qt.UserRole + 1001
    ROLE_ASSOCIATED_DATA_STR = Qt.UserRole + 1002
    ROLE_TXID_STR = Qt.UserRole + 1003
    key_role = ROLE_ID_STR

    def __init__(self, parent: 'ViewBroadcastTab', main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_columns=[self.Columns.DATA]
        )
        self.wallet = main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.current_asset = None
        self.current_broadcasts = None
        self.last_selected_broadcast_id = None

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                parent.update_associated_data_trigger.emit(None, None, None)
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.HEIGHT)
            self.last_selected_broadcast_id = m.data(self.ROLE_ID_STR)
            tx_hash = m.data(self.ROLE_TXID_STR)
            m = self.model().index(first_row, self.Columns.DATA)
            associated_data = m.data(self.ROLE_ASSOCIATED_DATA_STR)
            parent.update_associated_data_trigger.emit(self.current_asset, associated_data, tx_hash)

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        broadcasts = self.wallet.adb.get_broadcasts(self.current_asset) if self.current_asset else []
        if broadcasts == self.current_broadcasts:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (associated_data, timestamp, height, tx_hash, tx_pos) in enumerate(broadcasts):
            labels = [""] * len(self.Columns)
            labels[self.Columns.HEIGHT] = str(height)
            if associated_data[:2] == 'Qm':
                converted_message = associated_data
            else:
                converted_message = base_decode(associated_data, base=58)[2:].hex()
            labels[self.Columns.DATA] = converted_message
            labels[self.Columns.TIMESTAMP] = str(timestamp)
            row_item = [QStandardItem(x) for x in labels]
            id = f'{tx_hash}:{tx_pos}'
            row_item[self.Columns.HEIGHT].setData(id, self.ROLE_ID_STR)
            row_item[self.Columns.HEIGHT].setData(tx_hash, self.ROLE_TXID_STR)
            row_item[self.Columns.DATA].setData(associated_data, self.ROLE_ASSOCIATED_DATA_STR)
            self.model().insertRow(idx, row_item)
            self.refresh_row(converted_message, idx)
            if id == self.last_selected_broadcast_id:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_broadcasts = broadcasts
        self.filter()

    def refresh_row(self, key: str, row: int) -> None:
        assert row is not None
        row_item = [self.std_model.item(row, col) for col in self.Columns]
        row_item[self.Columns.DATA].setToolTip(key)


class ViewBroadcastTab(QWidget, Logger, MessageBoxMixin):
    update_asset_trigger = pyqtSignal(str)
    update_associated_data_trigger = pyqtSignal(str, str, str)

    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.window = window
        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        self.asset_list = BroadcastAssetList(self, window)
        vbox.addWidget(self.asset_list)
        hbox.addLayout(vbox)
        vbox = QVBoxLayout()
        self.broadcast_list = BroadcastList(self, window)
        vbox.addWidget(self.broadcast_list, stretch=1)

        self.ipfs_viewer = IPFSViewer(window)
        self.source_seperator = QHSeperationLine()
        self.source_seperator.setVisible(False)
        self.main_source_label = QLabel(_('Broadcast Source'))
        self.main_source_label.setVisible(False)
        self.main_source_txid = AutoResizingTextEdit()
        self.main_source_txid.setReadOnly(True)
        self.main_source_txid.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.main_source_txid.setAlignment(Qt.AlignVCenter)
        self.main_source_txid.setVisible(False)
        self.main_source_button = EnterButton(_('View Transaction'), lambda: self._show_source_tx(self.main_source_txid))
        self.main_source_button.setVisible(False)

        scroll_widget = QWidget()
        scroll_box = QVBoxLayout(scroll_widget)
        scroll_box.addWidget(self.ipfs_viewer)
        scroll_box.addWidget(self.source_seperator)
        scroll_box.addWidget(self.main_source_label)
        scroll_box.addWidget(self.main_source_txid)
        scroll_box.addWidget(self.main_source_button)
        scroll_box.addStretch()

        scroll = QScrollArea()
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        vbox.addWidget(scroll, stretch=1)
        hbox.addLayout(vbox)

        menu = MyMenu(window.config)
        menu.addConfig(_('Download IPFS'), window.config.cv.DOWNLOAD_IPFS, callback=self.ipfs_viewer.update_visibility)
        menu.addConfig(_('Display Downloaded IPFS'), window.config.cv.SHOW_IPFS, callback=self.ipfs_viewer.update_visibility)
        menu.addConfig(_('Show Metadata Sources'), window.config.cv.SHOW_METADATA_SOURCE, callback=self.update_visibility)
        menu.addConfig(_('Lookup IPFS using all gateways'), window.config.cv.ROUND_ROBIN_ALL_KNOWN_IPFS_GATEWAYS)

        toolbar_button = QToolButton()
        toolbar_button.setIcon(read_QIcon("preferences.png"))
        toolbar_button.setMenu(menu)
        toolbar_button.setPopupMode(QToolButton.InstantPopup)
        toolbar_button.setFocusPolicy(Qt.NoFocus)
        toolbar = QHBoxLayout()
        self.add_asset = QLineEdit()
        self.add_asset.setFixedWidth(200)
        self.add_asset.setMaxLength(32)
        toolbar.addWidget(self.add_asset)
        
        def watch_asset():
            asset = self.add_asset.text()
            if get_error_for_asset_typed(asset, AssetType.OWNER) and get_error_for_asset_typed(asset, AssetType.MSG_CHANNEL):
                self.show_warning(_('Not a valid owner asset or message channel.'))
                return
            window.wallet.adb.add_broadcast_to_watch(asset)
            self.add_asset.clear()
            self.update()

        self.watch_button = EnterButton(_('Watch Asset'), watch_asset)
        toolbar.addWidget(self.watch_button)
        toolbar.addStretch()
        toolbar.addWidget(toolbar_button)

        vbox = QVBoxLayout(self)
        vbox.addLayout(toolbar)
        vbox.addLayout(hbox)

        self.update_asset_trigger.connect(lambda x: self.switch_asset(x))
        self.update_associated_data_trigger.connect(lambda x, y, z: self.switch_associcated_data(x, y, z))

        self.searchable_list = SearchableListGrouping(self.asset_list, self.broadcast_list)

    def _show_source_tx(self, txid_widget):
        txid = txid_widget.toPlainText()
        self.window.do_process_from_txid(txid=txid)

    def update(self):
        self.asset_list.update()
        self.broadcast_list.update()
        self.ipfs_viewer.update_visibility()
        self.update_visibility()

    def update_visibility(self):
        for x in [self.source_seperator, self.main_source_button,
                  self.main_source_label, self.main_source_txid]:
            x.setVisible(self.window.config.SHOW_METADATA_SOURCE and bool(self.main_source_txid.toPlainText()))

    def switch_asset(self, asset: str):
        self.broadcast_list.current_asset = asset
        self.broadcast_list.update()
        self.switch_associcated_data(None, None, None)

    def switch_associcated_data(self, asset: str, associated_data: str, tx_hash: str):
        if not asset or not associated_data or not tx_hash:
            self.ipfs_viewer.clear()
            self.main_source_txid.clear()
        else:
            self.ipfs_viewer.update(asset, base_decode(associated_data, base=58))
            self.main_source_txid.setText(tx_hash)
        self.update_visibility()
