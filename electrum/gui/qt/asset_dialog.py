from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QScrollArea

from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.asset import AssetMetadata
from electrum.i18n import _
from electrum.network import UntrustedServerReturnedError
from electrum.util import trigger_callback

from .asset_view_panel import MetadataInfo
from .util import WindowModalDialog, Buttons, CloseButton

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class AssetDialog(WindowModalDialog):
    def __init__(self, window: 'ElectrumWindow', asset: str, *, parent=None):
        if parent is None:
            parent = window
        WindowModalDialog.__init__(self, parent, _("Asset"))
        self.asset = asset
        self.ipfs = None
        self.window = window
        self.wallet = window.wallet
        self.network = window.network
        self.saved = True
        self.valid = False

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        local_metadata = self.wallet.adb.get_asset_metadata(asset)
        type_text = None
        verifier_string_data = None
        verifier_string_text = None
        freeze_data = None
        freeze_text = None
        if local_metadata is None:
            if not window.network:
                self.window.show_message(_("You are offline."))
                return
            try:
                d = self.network.run_from_another_thread(
                    self.network.get_asset_metadata(asset))
                
                if not d:
                    self.window.show_message(_("This asset does not exist."))
                    return
                
                metadata = AssetMetadata(
                    sats_in_circulation=d['sats_in_circulation'],
                    divisions = d['divisions'],
                    reissuable = d['reissuable'],
                    associated_data = d['ipfs'] if d['has_ipfs'] else None
                )
                if metadata.is_associated_data_ipfs:
                    self.ipfs = metadata.associated_data_as_ipfs()
                metadata_sources = (
                    bytes.fromhex(d['source']['tx_hash']), 
                    bytes.fromhex(d['source_divisions']['tx_hash']) if 'source_divisions' in d else None,
                    bytes.fromhex(d['source_ipfs']['tx_hash']) if 'source_ipfs' in d else None)
                
                if asset[0] == '$':
                    d = self.network.run_from_another_thread(
                        self.network.get_verifier_string_for_restricted_asset(asset)
                    )
                    if d:
                        verifier_string_data = d

                    d = self.network.run_from_another_thread(
                        self.network.get_freeze_status_for_restricted_asset(asset)
                    )
                    if d:
                        freeze_data = d

            except UntrustedServerReturnedError as e:
                self.logger.info(f"Error getting info from network: {repr(e)}")
                self.window.show_message(
                    _("Error getting info from network") + ":\n" + e.get_message_for_gui()
                )
                return
            except Exception as e:
                self.window.show_message(
                    _("Error getting info from network") + ":\n" + repr(e)
                )
                return
        else:
            metadata, metadata_source = local_metadata
            if metadata.is_associated_data_ipfs():
                self.ipfs = metadata.associated_data_as_ipfs()
            if metadata_source == METADATA_UNCONFIRMED:
                type_text = _('UNCONFIRMED')
            elif metadata_source == METADATA_UNVERIFIED:
                type_text = _('NOT VERIFIED!')
            metadata_sources = self.wallet.adb.get_asset_metadata_txids(asset)
            if asset[0] == '$':
                verifier_string_data_tup = self.wallet.adb.get_restricted_verifier_string(asset)
                if verifier_string_data_tup:
                    verifier_string_data, verifier_string_type_id = verifier_string_data_tup
                    if verifier_string_type_id == METADATA_UNCONFIRMED:
                        verifier_string_text = _('UNCONFIRMED')
                    elif verifier_string_type_id == METADATA_UNVERIFIED:
                        verifier_string_text = _('NOT VERIFIED!')

                freeze_data_tup = self.wallet.adb.get_restricted_freeze(asset)
                if freeze_data_tup:
                    freeze_data, freeze_type_id = freeze_data_tup
                    if freeze_type_id == METADATA_UNCONFIRMED:
                        freeze_text = _('UNCONFIRMED')
                    elif freeze_type_id == METADATA_UNVERIFIED:
                        freeze_text = _('NOT VERIFIED!')
        
        self.m = MetadataInfo(self.window)
        self.m.update(asset, type_text, metadata, metadata_sources,
                    verifier_string_text, verifier_string_data, 
                    freeze_text, freeze_data)
        
        scroll = QScrollArea()
        scroll.setWidget(self.m)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        vbox.addWidget(scroll)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.valid = True


    def closeEvent(self, event):
        self.m.ipfs_viewer.unregister_callbacks()
        if self.ipfs:
            trigger_callback('ipfs_hash_dissociate_asset', self.ipfs, self.asset)
        event.accept()

