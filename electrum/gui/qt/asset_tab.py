from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QSizePolicy, QWidget, QTabWidget, QHBoxLayout, QToolButton

from electrum.logging import Logger
from electrum.i18n import _

from .my_treeview import MyMenu
from .util import MessageBoxMixin, read_QIcon
from .asset_view_panel import ViewAssetPanel
from .asset_management_panel import CreateAssetPanel, ReissueAssetPanel
from .asset_qualifier_tag_panel import QualifierAssetPanel
from .asset_freeze_tag_panel import ViewFreezePanel
from .asset_broadcast_panel import MakeBroadcastPanel

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class DummySearchableList:
    def filter(self, x):
        pass

class AssetTab(QWidget, MessageBoxMixin, Logger):
    
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.network = window.network

        self.view_asset_tab = ViewAssetPanel(self)

        if self.wallet.is_watching_only():
            self.create_asset_tab = QLabel(_('Watch only wallets cannot create assets'))
            self.create_asset_tab.setAlignment(Qt.AlignCenter)
        else:
            self.create_asset_tab = CreateAssetPanel(self)

        if self.wallet.is_watching_only():
            self.reissue_asset_tab = QLabel(_('Watch only wallets cannot reissue assets'))
            self.reissue_asset_tab.setAlignment(Qt.AlignCenter)
        else:
            self.reissue_asset_tab = ReissueAssetPanel(self)

        if self.wallet.is_watching_only():
            self.qualifiy_tab = QLabel(_('Watch only wallets cannot qualify assets'))
            self.qualifiy_tab.setAlignment(Qt.AlignCenter)
        else:
            self.qualifiy_tab = QualifierAssetPanel(self)

        if self.wallet.is_watching_only():
            self.freeze_tab = QLabel(_('Watch only wallets cannot freeze assets'))
            self.freeze_tab.setAlignment(Qt.AlignCenter)
        else:
            self.freeze_tab = ViewFreezePanel(self)

        if self.wallet.is_watching_only():
            self.broadcast_tab = QLabel(_('Watch only wallets cannot broadcast assets'))
            self.broadcast_tab.setAlignment(Qt.AlignCenter)
        else:
            self.broadcast_tab = MakeBroadcastPanel(self)

        menu = MyMenu(window.config)
        menu.addConfig(_('Download IPFS'), window.config.cv.DOWNLOAD_IPFS, callback=self.view_asset_tab.metadata_viewer.metadata_info.ipfs_viewer.update_visibility)
        menu.addConfig(_('Display Downloaded IPFS'), window.config.cv.SHOW_IPFS, callback=self.view_asset_tab.metadata_viewer.metadata_info.ipfs_viewer.update_visibility)
        def maybe_update_manage_tabs():
            if self.wallet.is_watching_only():
                return
            self.reissue_asset_tab.update()
            self.create_asset_tab.update()
        menu.addConfig(_('Control Asset Address'), window.config.cv.SHOW_CREATE_ASSET_PAY_TO, callback=maybe_update_manage_tabs)
        menu.addConfig(_('Display Unconfirmed Information'), window.config.cv.HANDLE_UNCONFIRMED_METADATA, callback=self.update)
        menu.addConfig(_('Show Metadata Sources'), window.config.cv.SHOW_METADATA_SOURCE, callback=self.view_asset_tab.update)
        menu.addConfig(_('Lookup IPFS using all gateways'), window.config.cv.ROUND_ROBIN_ALL_KNOWN_IPFS_GATEWAYS)

        is_hardware = self.wallet.keystore and self.wallet.keystore.get_type_text()[:2] == 'hw'

        toolbar_button = QToolButton()
        toolbar_button.setIcon(read_QIcon("preferences.png"))
        toolbar_button.setMenu(menu)
        toolbar_button.setPopupMode(QToolButton.InstantPopup)
        toolbar_button.setFocusPolicy(Qt.NoFocus)
        toolbar = QHBoxLayout()
        if not is_hardware:
            toolbar.addWidget(QLabel(_('Select a tab below to view, create, and manage your assets')))
        toolbar.addStretch()
        toolbar.addWidget(toolbar_button)

        self.searchable_list = self.view_asset_tab.asset_list


        vbox = QVBoxLayout(self)
        vbox.addLayout(toolbar)
        if is_hardware:
            vbox.addWidget(self.view_asset_tab)
        else:
            self.tabs = tabs = QTabWidget(self)
            tabs.addTab(self.view_asset_tab, read_QIcon("eye1.png"), _('View'))
            tabs.addTab(self.create_asset_tab, read_QIcon("unconfirmed.png"), _('Create'))
            tabs.addTab(self.reissue_asset_tab, read_QIcon("reissue.png"), _('Reissue'))
            tabs.addTab(self.qualifiy_tab, read_QIcon("tag.png"), _('Tagging'))
            tabs.addTab(self.freeze_tab, read_QIcon("freeze.png"), _('Freezing'))
            tabs.addTab(self.broadcast_tab, read_QIcon("broadcast_send.png"), _('Broadcast'))

            tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

            vbox.addWidget(self.tabs)

            def on_change_tab(index):
                if index == 0:
                    self.searchable_list = self.view_asset_tab.asset_list
                elif index == 3 and not self.wallet.is_watching_only():
                    self.searchable_list = self.qualifiy_tab.searchable_list_grouping
                elif index == 4 and not self.wallet.is_watching_only():
                    self.searchable_list = self.freeze_tab.asset_list
                else:
                    self.searchable_list = DummySearchableList()
            tabs.currentChanged.connect(on_change_tab)

    def update(self):
        self.view_asset_tab.update()        
        if not self.wallet.is_watching_only():
            self.create_asset_tab.update()
            self.reissue_asset_tab.update()
            self.qualifiy_tab.update()
            self.freeze_tab.update()
            self.broadcast_tab.update()
        super().update()
