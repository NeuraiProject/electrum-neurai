# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php.
"""Overview page (the wallet's front page), after neurai-qt's OverviewPage:
an XNA balance card with quick actions, an asset balance card with a search
field and a card with the most recent transactions."""

import heapq
from decimal import Decimal, ROUND_DOWN
from typing import TYPE_CHECKING, Optional, Dict, List, Tuple

from PyQt5.QtCore import (Qt, QSize, QRect, QRectF, QTimer, QModelIndex, QSortFilterProxyModel,
                          QDateTime, QLocale)
from PyQt5.QtGui import (QStandardItemModel, QStandardItem, QPainter, QPainterPath, QColor,
                         QFontMetrics, QFont, QIcon)
from PyQt5.QtWidgets import (QWidget, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QPushButton, QLineEdit, QListView, QAbstractItemView,
                             QStyledItemDelegate, QStyleOptionViewItem, QMenu, QSizePolicy,
                             QStyle)

from electrum import constants
from electrum.i18n import _
from electrum.logging import Logger
from electrum.util import profiler
from electrum.asset import ASSET_OWNER_IDENTIFIER

from . import neurai_theme
from .neurai_theme import tokens, theme_font, make_card, add_shadow

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


NUM_RECENT_TXS = 8     # like neurai-qt (NUM_ITEMS)
TX_ROW_HEIGHT = 54     # DECORATION_SIZE of neurai-qt
ASSET_ROW_HEIGHT = 52
CARD_MARGINS = (15, 9, 15, 10)  # neurai-qt: 1 px border + "padding: 8px 6px 4px 6px" + layout margins

ROLE_TXID = Qt.UserRole + 1
ROLE_AMOUNT = Qt.UserRole + 2
ROLE_CONFIRMED = Qt.UserRole + 3
ROLE_ASSET = Qt.UserRole + 4
ROLE_SUBTITLE = Qt.UserRole + 5
ROLE_AMOUNT_TEXT = Qt.UserRole + 6
ROLE_ICON = Qt.UserRole + 7
ROLE_ADMIN = Qt.UserRole + 8
ROLE_NAME = Qt.UserRole + 9


def format_compact(amount: int, decimal_point: int, unit: str) -> str:
    """neurai-qt's NeuraiUnits::formatCompactWithUnit: two decimals, K/M/B
    suffixes, never rounded up."""
    coin = 10 ** decimal_point
    n_abs = abs(amount)
    for scale, suffix in ((10 ** 9, 'B'), (10 ** 6, 'M'), (10 ** 3, 'K'), (1, '')):
        if scale > 1 and n_abs // coin < scale:
            continue
        divisor = coin * scale
        whole, remainder = divmod(n_abs, divisor)
        cents = remainder // (divisor // 100) if divisor >= 100 else remainder * 100 // divisor
        text = f'{whole}.{cents:02d}{suffix}'
        return ('-' if amount < 0 else '') + text + ' ' + unit
    return ''


def format_truncated(amount: int, decimal_point: int, unit: str, decimals: int = 2) -> str:
    """neurai-qt's formatWithUnitTruncated: a big total that fits, with the
    thousands grouped and the decimals cut (not rounded)."""
    value = (Decimal(amount) / (Decimal(10) ** decimal_point)).quantize(
        Decimal(1).scaleb(-decimals), rounding=ROUND_DOWN)
    integer, _sep, fract = f'{abs(value):f}'.partition('.')
    integer = '{:,}'.format(int(integer)).replace(',', ' ')
    text = integer + ('.' + fract if fract else '')
    return ('-' if value < 0 else '') + text + ' ' + unit


def format_asset_amount(amount: int) -> str:
    """Asset amounts (8 decimals at most), without trailing zeros."""
    value = Decimal(amount) / Decimal(10 ** 8)
    integer, _sep, fract = f'{abs(value):.8f}'.partition('.')
    fract = fract.rstrip('0')
    text = '{:,}'.format(int(integer)).replace(',', ' ') + ('.' + fract if fract else '')
    return ('-' if value < 0 else '') + text


class TxDelegate(QStyledItemDelegate):
    """Row of the recent transactions list (neurai-qt's TxViewDelegate): a
    tinted badge with the type icon, address or label and amount on the first
    line, date and asset on the second one."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._icon_cache = {}  # (icon, rgba) -> QIcon

    def _icon(self, name: str, color: QColor) -> QIcon:
        key = (name, color.rgba())
        icon = self._icon_cache.get(key)
        if icon is None:
            icon = neurai_theme.single_color_icon(neurai_theme.icon_path(name), color)
            self._icon_cache[key] = icon
        return icon

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        t = tokens()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = option.rect.adjusted(4, 0, -4, 0)
        if option.state & QStyle.State_MouseOver:
            path = QPainterPath()
            path.addRoundedRect(QRectF(option.rect.adjusted(0, 2, 0, -2)), 8, 8)
            painter.fillPath(path, t.surface_alt)

        amount = index.data(ROLE_AMOUNT) or 0
        confirmed = bool(index.data(ROLE_CONFIRMED))
        accent = t.text_muted if not confirmed else (t.error if amount < 0 else t.success)

        badge_size = 34
        badge = QRect(rect.left(), rect.center().y() - badge_size // 2 + 1, badge_size, badge_size)
        path = QPainterPath()
        path.addRoundedRect(QRectF(badge), 8, 8)
        painter.fillPath(path, neurai_theme.with_alpha(accent, 60 if neurai_theme.is_dark() else 36))
        self._icon(index.data(ROLE_ICON) or 'tx_inout', accent).paint(painter, badge.adjusted(7, 7, -7, -7))

        xspace = badge_size + 12
        ypad = 9
        half = (rect.height() - 2 * ypad) // 2
        top = QRect(rect.left() + xspace, rect.top() + ypad, rect.width() - xspace, half)
        bottom = QRect(rect.left() + xspace, rect.top() + ypad + half, rect.width() - xspace, half)

        amount_text = index.data(ROLE_AMOUNT_TEXT) or ''
        title_font = theme_font(QFont.DemiBold, 13)
        painter.setFont(title_font)
        fm = QFontMetrics(title_font)
        amount_width = fm.horizontalAdvance(amount_text)
        title = fm.elidedText(index.data(Qt.DisplayRole) or '', Qt.ElideMiddle, max(0, top.width() - amount_width - 12))
        painter.setPen(t.text)
        painter.drawText(top, Qt.AlignLeft | Qt.AlignVCenter, title)
        painter.setPen(accent)
        painter.drawText(top, Qt.AlignRight | Qt.AlignVCenter, amount_text)

        sub_font = theme_font(QFont.Normal, 12)
        painter.setFont(sub_font)
        fm = QFontMetrics(sub_font)
        painter.setPen(t.text_muted)
        asset = index.data(ROLE_ASSET) or ''
        asset_width = fm.horizontalAdvance(asset)
        subtitle = fm.elidedText(index.data(ROLE_SUBTITLE) or '', Qt.ElideRight, max(0, bottom.width() - asset_width - 12))
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter, subtitle)
        painter.drawText(bottom, Qt.AlignRight | Qt.AlignVCenter, asset)

        if index.row() + 1 < index.model().rowCount():
            painter.setPen(t.border)
            painter.drawLine(rect.left(), option.rect.bottom(), rect.right(), option.rect.bottom())
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(TX_ROW_HEIGHT, TX_ROW_HEIGHT)


class AssetDelegate(QStyledItemDelegate):
    """Row of the asset list (neurai-qt's AssetViewDelegate): a round badge
    with the initial of the asset, its name and kind, and the amount."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        t = tokens()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = option.rect.adjusted(4, 0, -12, 0)
        if option.state & QStyle.State_MouseOver:
            path = QPainterPath()
            path.addRoundedRect(QRectF(option.rect.adjusted(0, 2, -8, -2)), 8, 8)
            painter.fillPath(path, t.surface_alt)

        name = index.data(ROLE_NAME) or ''
        admin = bool(index.data(ROLE_ADMIN))
        depin = name.startswith('&')
        badge_text = t.success if depin else (t.primary if admin else t.text_muted)
        badge_size = 34
        badge = QRect(rect.left(), rect.center().y() - badge_size // 2 + 1, badge_size, badge_size)
        painter.setPen(Qt.NoPen)
        painter.setBrush(neurai_theme.with_alpha(badge_text, 60 if neurai_theme.is_dark() else 30))
        painter.drawEllipse(badge)
        badge_font = theme_font(QFont.DemiBold, 14)
        painter.setFont(badge_font)
        painter.setPen(badge_text)
        initial = name[:1].upper()
        if initial in ('$', '#', '&'):
            initial = name[1:2].upper()
        painter.drawText(badge, Qt.AlignCenter, initial)

        xspace = badge_size + 12
        ypad = 8
        half = (rect.height() - 2 * ypad) // 2
        top = QRect(rect.left() + xspace, rect.top() + ypad, rect.width() - xspace, half)
        bottom = QRect(rect.left() + xspace, rect.top() + ypad + half, rect.width() - xspace, half)

        amount_text = index.data(ROLE_AMOUNT_TEXT) or ''
        name_font = theme_font(QFont.DemiBold, 14)
        painter.setFont(name_font)
        fm = QFontMetrics(name_font)
        amount_width = fm.horizontalAdvance(amount_text)
        painter.setPen(t.text)
        painter.drawText(top, Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(name, Qt.ElideRight, max(0, top.width() - amount_width - 12)))
        painter.drawText(top.adjusted(0, 0, 0, half), Qt.AlignRight | Qt.AlignVCenter, amount_text)

        sub_font = theme_font(QFont.Normal, 12)
        painter.setFont(sub_font)
        painter.setPen(t.text_muted)
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter, index.data(ROLE_SUBTITLE) or '')

        if index.row() + 1 < index.model().rowCount():
            painter.setPen(t.border)
            painter.drawLine(rect.left(), option.rect.bottom(), option.rect.right() - 12, option.rect.bottom())
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(ASSET_ROW_HEIGHT, ASSET_ROW_HEIGHT)


class _CardList(QListView):
    """List of a card: transparent, no frame, rows highlighted on hover."""

    def __init__(self):
        super().__init__()
        self.setObjectName('overviewList')
        self.setFrameShape(QFrame.NoFrame)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setMouseTracking(True)
        self.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.setFocusPolicy(Qt.NoFocus)
        self.viewport().setAutoFillBackground(False)
        self.viewport().setCursor(Qt.PointingHandCursor)


class OverviewPage(QWidget, Logger):

    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)
        self.window = window
        self.wallet = window.wallet
        self.config = window.config
        self.setObjectName('overviewPage')
        self._pending_refresh = False
        self._recent_key = None
        self._counterparty_cache = {}  # (txid, asset, incoming) -> address
        self._asset_rows = None
        # Coalesce the bursts of updates during synchronization
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(150)
        self._refresh_timer.timeout.connect(self._do_refresh)

        self.balance_card = self._build_balance_card()
        self.asset_card = self._build_asset_card()
        self.tx_card = self._build_tx_card()

        left = QVBoxLayout()
        left.setSpacing(20)
        left.setContentsMargins(0, 0, 0, 0)
        left.addWidget(self.balance_card)
        left.addWidget(self.asset_card, 1)

        right = QVBoxLayout()
        right.setSpacing(20)
        right.setContentsMargins(0, 0, 0, 0)
        right.addWidget(self.tx_card, 1)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        layout.addLayout(left, 1)
        layout.addLayout(right, 1)

    # ------------------------------------------------------------------ cards

    def _card(self, title: str) -> Tuple[QFrame, QVBoxLayout, QHBoxLayout, QPushButton]:
        card = QFrame()
        card.setFrameShape(QFrame.NoFrame)
        make_card(card)
        add_shadow(card)
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(*CARD_MARGINS)
        vbox.setSpacing(10)
        title_row = QHBoxLayout()
        title_row.setSpacing(6)
        title_label = QLabel(title)
        title_label.setObjectName('cardTitle')
        title_row.addWidget(title_label)
        # out-of-sync warning, as in neurai-qt
        warning = QPushButton()
        warning.setFlat(True)
        warning.setIcon(neurai_theme.neurai_icon('warning', tokens().warning))
        warning.setIconSize(QSize(18, 18))
        warning.setFixedSize(QSize(26, 26))
        warning.setCursor(Qt.PointingHandCursor)
        warning.setToolTip(_('The displayed information may be out of date. Your wallet automatically '
                             'synchronizes with the Neurai network after a connection is established, '
                             'but this process has not completed yet.'))
        warning.clicked.connect(self._on_warning_clicked)
        warning.setVisible(False)
        title_row.addWidget(warning)
        vbox.addLayout(title_row)
        return card, vbox, title_row, warning

    @staticmethod
    def _line() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Plain)
        return line

    def _build_balance_card(self) -> QFrame:
        card, vbox, title_row, self.balance_warning = self._card(_('{} Balances').format(constants.net.SHORT_NAME))
        self.balance_title_row = title_row
        title_row.addStretch(1)
        self.watch_chip = QLabel(_('WATCH-ONLY'))
        self.watch_chip.setObjectName('walletChip')
        self.watch_chip.setToolTip(_('This wallet is watching-only: it cannot sign transactions.'))
        self.watch_chip.setVisible(self.wallet.is_watching_only())
        title_row.addWidget(self.watch_chip)
        vbox.addWidget(self._line())

        grid = QGridLayout()
        grid.setSpacing(12)  # as gridLayout of neurai-qt's overviewpage.ui
        grid.setContentsMargins(0, 0, 0, 5)
        self.balance_rows = {}

        def add_row(key, row, caption, tooltip):
            caption_label = QLabel(caption)
            caption_label.setObjectName('cardCaption')
            value = QLabel()
            value.setObjectName('cardValue')
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setToolTip(tooltip)
            grid.addWidget(caption_label, row, 0)
            grid.addWidget(value, row, 1)
            self.balance_rows[key] = (caption_label, value)

        add_row('available', 0, _('Available:'), _('Your current spendable balance'))
        add_row('pending', 1, _('Pending:'), _('Total of transactions that have yet to be confirmed, '
                                               'and do not yet count toward the spendable balance'))
        add_row('immature', 2, _('Immature:'), _('Mined balance that has not yet matured'))
        add_row('frozen', 3, _('Frozen:'), _('Coins and addresses you have frozen: they are not spent '
                                             'until you unfreeze them'))
        grid.addWidget(self._line(), 4, 0, 1, 2)
        total_caption = QLabel(_('Total:'))
        total_caption.setObjectName('cardCaption')
        self.total_label = QLabel()
        self.total_label.setObjectName('cardTotal')
        self.total_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.total_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid.addWidget(total_caption, 5, 0)
        grid.addWidget(self.total_label, 5, 1)
        self.fiat_label = QLabel()
        self.fiat_label.setObjectName('cardHint')
        self.fiat_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.fiat_label, 6, 1)
        grid.setColumnStretch(2, 1)
        vbox.addLayout(grid)

        # Quick actions under the balance, as in neurai-qt and the web wallet
        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.setContentsMargins(0, 4, 0, 4)
        self.send_button = QPushButton(_('Send'))
        self.send_button.setProperty('primary', True)
        self.send_button.clicked.connect(self.window.show_send_tab)
        self.receive_button = QPushButton(_('Receive'))
        self.receive_button.clicked.connect(self.window.show_receive_tab)
        self.create_asset_button = QPushButton(_('Create asset'))
        self.create_asset_button.clicked.connect(self.window.show_create_asset)
        for b in (self.send_button, self.receive_button, self.create_asset_button):
            b.setCursor(Qt.PointingHandCursor)
            actions.addWidget(b)
        actions.addStretch(1)
        vbox.addLayout(actions)
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        return card

    def _build_asset_card(self) -> QFrame:
        card, vbox, title_row, self.asset_warning = self._card(_('Asset Balances'))
        vbox.setSpacing(12)
        # the search field takes the rest of the header row, as in neurai-qt
        self.asset_search = QLineEdit()
        self.asset_search.setObjectName('overviewSearch')
        self.asset_search.setPlaceholderText(_('Search'))
        self.asset_search.setClearButtonEnabled(True)
        self.asset_search.setFixedHeight(30)
        self.asset_search.setAttribute(Qt.WA_MacShowFocusRect, False)
        title_row.addSpacing(6)
        title_row.addWidget(self.asset_search, 1)
        vbox.addWidget(self._line())

        self.asset_model = QStandardItemModel(self)
        self.asset_proxy = QSortFilterProxyModel(self)
        self.asset_proxy.setSourceModel(self.asset_model)
        self.asset_proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.asset_proxy.setFilterRole(ROLE_NAME)
        # Delay before filtering, as in neurai-qt
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._apply_asset_filter)
        self.asset_search.textChanged.connect(lambda _t: self._search_timer.start())

        self.asset_list = _CardList()
        self.asset_list.setItemDelegate(AssetDelegate(self.asset_list))
        self.asset_list.setModel(self.asset_proxy)
        self.asset_list.setMinimumHeight(2 * ASSET_ROW_HEIGHT)
        self.asset_list.clicked.connect(self._on_asset_clicked)
        self.asset_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.asset_list.customContextMenuRequested.connect(self._asset_context_menu)
        self.asset_list.setToolTip(_('Click an asset to see its details. Right-click for more actions.'))
        vbox.addWidget(self.asset_list, 1)
        self.asset_empty = QLabel(_('No assets in this wallet yet.'))
        self.asset_empty.setObjectName('emptyHint')
        self.asset_empty.setAlignment(Qt.AlignCenter)
        vbox.addWidget(self.asset_empty, 1)
        self.asset_empty.hide()
        return card

    def _build_tx_card(self) -> QFrame:
        card, vbox, title_row, self.tx_warning = self._card(_('Recent transactions'))
        title_row.addStretch(1)
        self.history_link = QPushButton(_('View all'))
        self.history_link.setFlat(True)
        self.history_link.setCursor(Qt.PointingHandCursor)
        self.history_link.setStyleSheet(f'QPushButton {{ color: {neurai_theme.css(tokens().primary)}; padding: 2px 4px; }}'
                                        f'QPushButton:hover {{ color: {neurai_theme.css(tokens().primary_hover)}; }}')
        self.history_link.clicked.connect(self.window.show_history_tab)
        title_row.addWidget(self.history_link)

        self.tx_model = QStandardItemModel(self)
        self.tx_list = _CardList()
        self.tx_list.setItemDelegate(TxDelegate(self.tx_list))
        self.tx_list.setModel(self.tx_model)
        self.tx_list.setMinimumHeight(3 * (TX_ROW_HEIGHT + 2))
        self.tx_list.clicked.connect(self._on_tx_clicked)
        self.tx_list.setToolTip(_('Click a transaction to see its details.'))
        vbox.addWidget(self.tx_list, 1)
        self.tx_empty = QLabel(_('No transactions yet.'))
        self.tx_empty.setObjectName('emptyHint')
        self.tx_empty.setAlignment(Qt.AlignCenter)
        vbox.addWidget(self.tx_empty, 1)
        self.tx_empty.hide()
        return card

    # ------------------------------------------------------------------ updates

    def refresh_data(self):
        """Refresh balances, assets and recent transactions. Deferred while the
        page is hidden, and coalesced, as the history of big wallets is long."""
        if not self.isVisible():
            self._pending_refresh = True
            return
        self._refresh_timer.start()

    def showEvent(self, e):
        super().showEvent(e)
        if self._pending_refresh:
            self._pending_refresh = False
            self._refresh_timer.start(0)

    def _do_refresh(self):
        if not self.window.wallet:
            return
        self.update_balances()
        self.update_assets()
        self.update_recent_transactions()

    def update_status(self, synced: bool):
        """Called with the network status: out-of-sync warnings."""
        for w in (self.balance_warning, self.asset_warning, self.tx_warning):
            if w.isHidden() != synced:
                w.setHidden(synced)

    def update_balances(self):
        wallet = self.wallet
        window = self.window
        confirmed, unconfirmed, unmatured, frozen, lightning, f_lightning = wallet.get_balances_for_piechart()
        unit = window.base_unit()
        fmt = window.config.format_amount_and_units
        values = {
            'available': confirmed + lightning,
            'pending': unconfirmed,
            'immature': unmatured,
            'frozen': frozen + f_lightning,
        }
        for key, (caption, value_label) in self.balance_rows.items():
            amount = values[key]
            value_label.setText(fmt(amount))
            # like neurai-qt, show immature (and frozen) only when there is some
            visible = key in ('available', 'pending') or amount != 0
            caption.setVisible(visible)
            value_label.setVisible(visible)
        total = sum(values.values())
        dp = window.get_decimal_point()
        self.total_label.setText(format_truncated(total, dp, unit))
        self.total_label.setToolTip(fmt(total))
        fiat = window.fx.format_amount_and_units(total) if window.fx and window.fx.is_enabled() else ''
        self.fiat_label.setText(f'≈ {fiat}' if fiat else '')
        self.fiat_label.setVisible(bool(fiat))
        self.watch_chip.setVisible(wallet.is_watching_only())

    def _asset_balances(self) -> List[Tuple[str, int, bool]]:
        """(name, amount, administrator) of the assets held, owner tokens merged
        into their asset as in neurai-qt's asset table."""
        wallet = self.wallet
        balances = {}
        for asset, balance in wallet.get_balance(asset_aware=True).items():
            if not asset or wallet.is_asset_in_blacklist(asset):
                continue
            amount = sum(balance)
            if amount > 0:
                balances[asset] = amount
        rows = []
        for asset, amount in balances.items():
            if asset.endswith(ASSET_OWNER_IDENTIFIER):
                if asset[:-1] in balances:
                    continue  # shown on the row of the asset
                rows.append((asset, amount, True))
            else:
                rows.append((asset, amount, asset + ASSET_OWNER_IDENTIFIER in balances))
        rows.sort(key=lambda r: r[0].lower())
        return rows

    def update_assets(self):
        rows = self._asset_balances()
        if rows == self._asset_rows:
            return
        self._asset_rows = rows
        self.asset_model.clear()
        for name, amount, admin in rows:
            item = QStandardItem(name)
            item.setData(name, ROLE_NAME)
            item.setData(admin, ROLE_ADMIN)
            item.setData(format_asset_amount(amount), ROLE_AMOUNT_TEXT)
            # the kind of asset under its name; the colour of the badge tells
            # administrator (owner token held) and DePIN assets, as in neurai-qt
            if name.startswith('&'):
                kind = _('DePIN asset')
            elif admin:
                kind = _('Administrator')
            elif name.startswith('#'):
                kind = _('Qualifier')
            elif name.startswith('$'):
                kind = _('Restricted asset')
            elif '~' in name:
                kind = _('Message channel')
            elif '#' in name:
                kind = _('Unique asset')
            else:
                kind = _('Asset')
            item.setData(kind, ROLE_SUBTITLE)
            item.setToolTip(f'{name}: {format_asset_amount(amount)}')
            item.setEditable(False)
            self.asset_model.appendRow(item)
        self._update_asset_empty_state()

    def _apply_asset_filter(self):
        self.asset_proxy.setFilterFixedString(self.asset_search.text().strip())
        self._update_asset_empty_state()

    def _update_asset_empty_state(self):
        has_rows = self.asset_proxy.rowCount() > 0
        if self.asset_model.rowCount() == 0:
            self.asset_empty.setText(_('No assets in this wallet yet.'))
        else:
            self.asset_empty.setText(_('No asset matches the search.'))
        self.asset_list.setVisible(has_rows)
        self.asset_empty.setVisible(not has_rows)

    def _recent_history(self, count: int) -> List[dict]:
        """The last transactions of the wallet, newest first, one row per asset.
        Only the latest transactions are looked at in detail, so that this stays
        fast on wallets with thousands of transactions."""
        wallet = self.wallet
        adb = wallet.adb
        tx_addrs = {}  # type: Dict[str, List[str]]
        sort_heights = {}  # type: Dict[str, int]
        for addr in wallet.get_addresses():
            for txid, height in adb.get_address_history(addr).items():
                tx_addrs.setdefault(txid, []).append(addr)
                sort_heights[txid] = adb.tx_height_to_sort_height(height)
        # the latest transactions by height (a transaction can give several
        # rows (assets) or none (blacklisted assets), hence the margin), and all
        # those of the lowest of these heights, to order them by block position
        latest = heapq.nlargest(count * 2, sort_heights.values())
        threshold = latest[-1] if latest else 0
        candidates = [txid for txid, h in sort_heights.items() if h >= threshold]
        mined = {txid: adb.get_tx_height(txid) for txid in candidates}

        def sort_key(txid):
            info = mined[txid]
            return adb.tx_height_to_sort_height(info.height), info.txpos or -1, txid

        rows = []
        for txid in sorted(candidates, key=sort_key, reverse=True):
            deltas = {}
            for addr in tx_addrs[txid]:
                for asset, value in adb.get_tx_delta(txid, addr).items():
                    deltas[asset] = deltas.get(asset, 0) + value
            for asset in sorted(deltas, key=lambda a: (a is not None, a or '')):
                if asset and wallet.is_asset_in_blacklist(asset):
                    continue
                rows.append({'txid': txid, 'asset': asset, 'delta': deltas[asset], 'mined': mined[txid]})
            if len(rows) >= count:
                break
        return rows[:count]

    def _counterparty(self, txid: str, asset: Optional[str], incoming: bool) -> str:
        """Address shown for a transaction without label: ours for an incoming
        payment, the recipient for an outgoing one."""
        key = (txid, asset, incoming)
        if key in self._counterparty_cache:
            return self._counterparty_cache[key]
        address = ''
        tx = self.wallet.adb.get_transaction(txid)
        if tx is not None:
            try:
                candidates = []
                for o in tx.outputs():
                    if not o.address:
                        continue
                    if incoming != self.wallet.is_mine(o.address):
                        continue
                    candidates.append(o)
                same_asset = [o for o in candidates if o.asset == asset]
                chosen = (same_asset or candidates)[:1]
                if chosen:
                    address = chosen[0].address
            except Exception:
                self.logger.exception('cannot read the outputs of {txid}')
        self._counterparty_cache[key] = address
        return address

    def _is_coinbase(self, txid: str) -> bool:
        """Mining reward (neurai-qt shows them with their own icon)."""
        key = (txid, 'coinbase')
        if key not in self._counterparty_cache:
            tx = self.wallet.adb.get_transaction(txid)
            try:
                coinbase = bool(tx is not None and tx.inputs() and tx.inputs()[0].is_coinbase_input())
            except Exception:
                coinbase = False
            self._counterparty_cache[key] = coinbase
        return self._counterparty_cache[key]

    @profiler(min_threshold=0.05)
    def update_recent_transactions(self):
        wallet = self.wallet
        if len(self._counterparty_cache) > 500:
            self._counterparty_cache.clear()
        rows = self._recent_history(NUM_RECENT_TXS)
        key = [(r['txid'], r['asset'], r['delta'], r['mined'].conf, r['mined'].height,
                wallet.get_label_for_txid(r['txid'])) for r in rows]
        key.append(self.window.base_unit())
        if key == self._recent_key:
            return
        self._recent_key = key
        unit = self.window.base_unit()
        locale = QLocale()
        self.tx_model.clear()
        for r in rows:
            txid, asset, delta, mined = r['txid'], r['asset'], r['delta'], r['mined']
            status, status_str = wallet.get_tx_status(txid, mined)
            confirmed = mined.conf > 0
            label = wallet.get_label_for_txid(txid)
            title = label or self._counterparty(txid, asset, delta > 0) or txid
            if mined.timestamp:
                dt = QDateTime.fromSecsSinceEpoch(int(mined.timestamp))
                date = locale.toString(dt.date(), QLocale.ShortFormat) + ' ' + dt.toString('hh:mm')
            else:
                date = status_str
            if asset:
                amount = format_asset_amount(delta)
                icon = 'tx_asset_input' if delta > 0 else 'tx_asset_output'
            else:
                amount = self.config.format_amount(delta)
                if delta > 0:
                    icon = 'tx_mined' if self._is_coinbase(txid) else 'tx_input'
                else:
                    icon = 'tx_output' if delta < 0 else 'tx_inout'
            if delta > 0 and not amount.startswith('+'):
                amount = '+' + amount
            if not confirmed:
                amount = f'[{amount}]'
            item = QStandardItem(title)
            item.setData(txid, ROLE_TXID)
            item.setData(delta, ROLE_AMOUNT)
            item.setData(confirmed, ROLE_CONFIRMED)
            item.setData(asset or unit, ROLE_ASSET)
            item.setData(date, ROLE_SUBTITLE)
            item.setData(amount, ROLE_AMOUNT_TEXT)
            item.setData(icon, ROLE_ICON)
            tip = [title, txid, status_str]
            item.setToolTip('\n'.join(x for x in tip if x))
            item.setEditable(False)
            self.tx_model.appendRow(item)
        has_rows = self.tx_model.rowCount() > 0
        self.tx_list.setVisible(has_rows)
        self.tx_empty.setVisible(not has_rows)

    # ------------------------------------------------------------------ actions

    def _on_warning_clicked(self):
        if self.window.network:
            self.window.gui_object.show_network_dialog()
        else:
            self.window.show_message(_('You are using Electrum in offline mode: the wallet does not synchronize.'),
                                     title=_('Offline'))

    def _on_tx_clicked(self, index: QModelIndex):
        txid = index.data(ROLE_TXID)
        if not txid:
            return
        tx = self.wallet.adb.get_transaction(txid)
        if tx:
            self.window.show_transaction(tx)

    def _on_asset_clicked(self, index: QModelIndex):
        name = index.data(ROLE_NAME)
        if name:
            self.window.show_asset(name)

    def _asset_context_menu(self, pos):
        index = self.asset_list.indexAt(pos)
        if not index.isValid():
            return
        name = index.data(ROLE_NAME)
        amount = index.data(ROLE_AMOUNT_TEXT)
        menu = QMenu(self)
        menu.addAction(_('View details'), lambda: self.window.show_asset(name))
        menu.addAction(_('Send asset'), lambda: self.window.show_send_tab(asset=name))
        menu.addSeparator()
        menu.addAction(_('Copy name'), lambda: self.window.do_copy(name, title=_('Asset name')))
        menu.addAction(_('Copy amount'), lambda: self.window.do_copy(amount.replace(' ', ''), title=_('Amount')))
        menu.exec_(self.asset_list.viewport().mapToGlobal(pos))
