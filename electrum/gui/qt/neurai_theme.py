# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php.
"""Visual theme of the Neurai Qt wallet (neurai-qt, src/qt/guitheme.cpp),
ported to Electrum: flat surfaces, rounded cards and fields, neutral greys
and a single orange accent, in a light and a dark variant.

apply() installs style, palette, font and the application-wide style sheet;
the helpers below (make_card, shadow_effect, navigation_icon...) give single
widgets the look of their neurai-qt counterparts.
"""

import sys
from typing import NamedTuple, Optional, Union

from PyQt5.QtCore import Qt, QSize, QObject, QEvent
from PyQt5.QtGui import (QColor, QPalette, QFont, QFontDatabase, QIcon, QImage, QPixmap,
                         QPainter)
from PyQt5.QtWidgets import QApplication, QStyleFactory, QWidget, QGraphicsDropShadowEffect, QPushButton

from electrum.util import resource_path
from electrum.logging import get_logger


_logger = get_logger(__name__)

# Font family used across the GUI (bundled in electrum/gui/fonts).
FONT_FAMILY = 'Inter'
FONT_FILES = ('Inter-Regular.ttf', 'Inter-Medium.ttf', 'Inter-SemiBold.ttf', 'Inter-Bold.ttf')

# Corner radius of cards and of input fields/buttons, in pixels.
CARD_RADIUS = 12
FIELD_RADIUS = 10

# Margins of neurai-qt's main window: the header card is 20 px from the
# window edges, the pages 30 px (also 30 px below the header).
HEADER_MARGIN = 20
PAGE_MARGIN = 30


class Tokens(NamedTuple):
    page: QColor          # window background
    surface: QColor       # cards, fields, tables
    surface_alt: QColor   # hover, alternate rows, read-only fields
    border: QColor        # card borders and dividers
    field_border: QColor  # input borders
    text: QColor          # primary text
    text_muted: QColor    # secondary text
    primary: QColor       # accent (buttons, active navigation)
    primary_hover: QColor
    primary_text: QColor  # text on top of the accent colour
    accent: QColor        # tinted surface for selections
    success: QColor
    warning: QColor
    error: QColor
    shadow: QColor


# Same values as neurai-qt (which follows the DaisyUI themes of the web
# wallet): warm "sand" neutrals in light mode, raised slate cards in dark mode.
LIGHT_TOKENS = Tokens(
    page=QColor('#ece8e2'),
    surface=QColor('#fffdfa'),
    surface_alt=QColor('#f6f2ec'),
    border=QColor('#ddd5ca'),
    field_border=QColor('#d0c6b9'),
    text=QColor('#111827'),
    text_muted=QColor('#67615a'),
    primary=QColor('#f97316'),
    primary_hover=QColor('#ea6c10'),
    primary_text=QColor('#ffffff'),
    accent=QColor('#fdeedf'),
    success=QColor('#16a34a'),
    warning=QColor('#d97706'),
    error=QColor('#ef4444'),
    shadow=QColor(68, 52, 36, 36),
)

DARK_TOKENS = Tokens(
    page=QColor('#090c11'),
    surface=QColor('#252f3e'),
    surface_alt=QColor('#2c3748'),
    border=QColor('#3c495c'),
    field_border=QColor('#4f5d72'),
    text=QColor('#f9fafb'),
    text_muted=QColor('#9ca3af'),
    primary=QColor('#f97316'),
    primary_hover=QColor('#ea6c10'),
    primary_text=QColor('#ffffff'),
    accent=QColor('#45362b'),
    success=QColor('#22c55e'),
    warning=QColor('#f59e0b'),
    error=QColor('#f87171'),
    shadow=QColor(0, 0, 0, 110),
)

_dark_mode = False


def is_dark() -> bool:
    return _dark_mode


def tokens() -> Tokens:
    """Tokens of the active theme (see apply)."""
    return DARK_TOKENS if _dark_mode else LIGHT_TOKENS


def icon_path(name: str) -> str:
    """Path of an icon copied from neurai-qt (electrum/gui/icons/neurai)."""
    if not name.endswith('.png'):
        name += '.png'
    return resource_path('gui', 'icons', 'neurai', name)


def font_path(name: str) -> str:
    return resource_path('gui', 'fonts', name)


def qss_url(path: str) -> str:
    """A file path for a quoted style sheet url("..."): Qt wants forward slashes,
    also on Windows (the quotes keep spaces and parentheses of the path)."""
    return path.replace('\\', '/').replace('"', '\\"')


def css(color: QColor) -> str:
    if color.alpha() == 255:
        return color.name()
    return f'rgba({color.red()}, {color.green()}, {color.blue()}, {color.alpha()})'


def with_alpha(color: QColor, alpha: int) -> QColor:
    c = QColor(color)
    c.setAlpha(alpha)
    return c


def blend(fg: QColor, bg: QColor, amount: float) -> QColor:
    """fg painted with the given opacity over bg, as an opaque colour."""
    a = max(0.0, min(1.0, amount))
    return QColor(round(fg.red() * a + bg.red() * (1 - a)),
                  round(fg.green() * a + bg.green() * (1 - a)),
                  round(fg.blue() * a + bg.blue() * (1 - a)))


def make_palette(t: Tokens, dark: bool) -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, t.page)
    p.setColor(QPalette.WindowText, t.text)
    p.setColor(QPalette.Base, t.surface)
    p.setColor(QPalette.AlternateBase, t.surface_alt)
    p.setColor(QPalette.ToolTipBase, t.text if dark else QColor('#111827'))
    p.setColor(QPalette.ToolTipText, t.page if dark else QColor('#ffffff'))
    p.setColor(QPalette.PlaceholderText, t.text_muted)
    p.setColor(QPalette.Text, t.text)
    p.setColor(QPalette.Button, t.surface)
    p.setColor(QPalette.ButtonText, t.text)
    p.setColor(QPalette.BrightText, t.error)
    p.setColor(QPalette.Link, t.primary)
    p.setColor(QPalette.LinkVisited, t.primary_hover)
    p.setColor(QPalette.Highlight, t.primary)
    p.setColor(QPalette.HighlightedText, t.primary_text)
    # Bevel colours used by Fusion for frames and separators.
    p.setColor(QPalette.Light, t.border if dark else QColor('#ffffff'))
    p.setColor(QPalette.Midlight, t.surface_alt)
    p.setColor(QPalette.Mid, t.field_border)
    p.setColor(QPalette.Dark, QColor('#0b1220') if dark else QColor('#9ca3af'))
    p.setColor(QPalette.Shadow, QColor('#000000') if dark else QColor('#6b7280'))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, t.text_muted)
    p.setColor(QPalette.Disabled, QPalette.Highlight, t.field_border)
    p.setColor(QPalette.Disabled, QPalette.Base, t.surface_alt)
    return p


# Application wide rules, from neurai-qt's guitheme.cpp, plus the rules for
# Electrum's own widgets at the end. Widgets that set their own style sheet
# keep working: their rules are merged on top of these.
STYLE_SHEET_TEMPLATE = r'''
QToolTip { background-color: @tooltipbg; color: @tooltiptext; border: none; border-radius: 6px; padding: 6px 8px; }

QMenuBar { background-color: @page; border: none; padding: 2px 6px; }
QMenuBar::item { background: transparent; padding: 5px 10px; border-radius: 6px; }
QMenuBar::item:selected { background-color: @border; }
QMenu { background-color: @surface; border: 1px solid @border; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 6px 22px 6px 30px; border-radius: 6px; color: @text; }
QMenu::item:selected { background-color: @accent; color: @text; }
QMenu::item:disabled { color: @muted; }
QMenu::icon { padding-left: 8px; }
QMenu::separator { height: 1px; background: @border; margin: 5px 8px; }
QMenu::indicator { width: 14px; height: 14px; left: 8px; border: 1px solid @fieldborder; border-radius: 4px; background-color: @surface; }
QMenu::indicator:checked { background-color: @primary; border-color: @primary; image: url("@icon_check"); }

QPushButton { background-color: @surface; color: @text; border: 1px solid @border; border-radius: @fieldradiuspx; padding: 7px 16px; font-weight: 600; }
QPushButton:hover { background-color: @surfalt; border-color: @fieldborder; }
QPushButton:pressed { background-color: @border; }
QPushButton:checked { background-color: @accent; border-color: @primary; color: @primary; }
QPushButton:disabled { color: @muted; background-color: @surfalt; border-color: @border; }
QPushButton:default, QPushButton[primary="true"] { background-color: @primary; color: @primtext; border-color: @primary; }
QPushButton:default:hover, QPushButton[primary="true"]:hover { background-color: @primhover; border-color: @primhover; }
QPushButton:default:disabled, QPushButton[primary="true"]:disabled { background-color: @primdisabled; border-color: @primdisabled; color: @primtext; }
QPushButton:flat { background: transparent; border: none; }
QPushButton[compact="true"] { padding: 2px 4px; font-weight: 600; }
QPushButton::menu-indicator { image: url("@icon_chevron_down"); subcontrol-origin: padding; subcontrol-position: center right; width: 10px; height: 10px; right: 4px; }

QToolButton { background: transparent; border: 1px solid transparent; border-radius: 8px; padding: 4px; color: @text; }
QToolButton:hover { background-color: @surfalt; border-color: @border; }
QToolButton:pressed, QToolButton:checked { background-color: @accent; border-color: @primary; }
QToolButton::menu-indicator { image: url("@icon_chevron_down"); subcontrol-origin: padding; subcontrol-position: bottom right; width: 8px; height: 8px; }

QLineEdit, QPlainTextEdit, QTextEdit, QAbstractSpinBox, QComboBox {
    background-color: @surface; color: @text; border: 1px solid @fieldborder; border-radius: @fieldradiuspx;
    padding: 5px 9px; selection-background-color: @primary; selection-color: @primtext;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QAbstractSpinBox:focus, QComboBox:focus { border-color: @primary; }
QLineEdit:disabled, QPlainTextEdit:disabled, QTextEdit:disabled, QAbstractSpinBox:disabled, QComboBox:disabled { background-color: @surfalt; color: @muted; }
QLineEdit[readOnly="true"], QPlainTextEdit[readOnly="true"], QTextEdit[readOnly="true"] { background-color: @surfalt; }
QTextEdit, QPlainTextEdit { padding: 4px 6px; }

QComboBox { padding-right: 26px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 24px; border: none; background: transparent; }
QComboBox::down-arrow { image: url("@icon_chevron_down"); width: 12px; height: 12px; }
QComboBox QAbstractItemView { background-color: @surface; color: @text; border: 1px solid @border; border-radius: 8px; padding: 4px; outline: 0; selection-background-color: @accent; selection-color: @text; }

QAbstractSpinBox { padding-right: 22px; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button { subcontrol-origin: border; width: 20px; border: none; background: transparent; }
QAbstractSpinBox::up-button { subcontrol-position: top right; margin-top: 2px; }
QAbstractSpinBox::down-button { subcontrol-position: bottom right; margin-bottom: 2px; }
QAbstractSpinBox::up-arrow { image: url("@icon_chevron_up"); width: 10px; height: 10px; }
QAbstractSpinBox::down-arrow { image: url("@icon_chevron_down"); width: 10px; height: 10px; }

QCheckBox, QRadioButton { spacing: 8px; background: transparent; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid @fieldborder; border-radius: 5px; background-color: @surface; }
QCheckBox::indicator:hover { border-color: @primary; }
QCheckBox::indicator:checked, QCheckBox::indicator:indeterminate { background-color: @primary; border-color: @primary; image: url("@icon_check"); }
QCheckBox::indicator:disabled { background-color: @surfalt; border-color: @border; }
QCheckBox::indicator:checked:disabled { background-color: @primdisabled; border-color: @primdisabled; }
QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid @fieldborder; border-radius: 9px; background-color: @surface; }
QRadioButton::indicator:hover { border-color: @primary; }
QRadioButton::indicator:checked { width: 8px; height: 8px; border: 5px solid @primary; border-radius: 9px; background-color: @surface; }
QRadioButton::indicator:disabled { background-color: @surfalt; border-color: @border; }

QTableView, QTreeView, QListView {
    background-color: @surface; alternate-background-color: @surfalt; color: @text; border: 1px solid @border;
    border-radius: @cardradiuspx; gridline-color: @border; outline: 0;
    selection-background-color: @accent; selection-color: @text;
}
QTableView::item:selected, QTreeView::item:selected, QListView::item:selected { background-color: @accent; color: @text; }
/* Rows of the lists ~30 px tall, as the tables of neurai-qt. Only a padding:
   a background or a border here would hide the colours the models give to
   their cells; the grid lines are drawn by MyTreeView.drawRow. */
QTreeView::item, QTableView::item { padding: 6px 0px; }
QTreeView::branch:has-children:closed { image: url("@icon_chevron_right"); }
QTreeView::branch:has-children:open { image: url("@icon_chevron_down"); }
QHeaderView { background: transparent; border: none; }
QHeaderView::section { background-color: @surface; color: @muted; border: none; border-bottom: 1px solid @border; padding: 7px 8px; font-weight: 600; }
QHeaderView::section:horizontal:first { border-top-left-radius: @cardradiuspx; }
QHeaderView::section:horizontal:last { border-top-right-radius: @cardradiuspx; }
QHeaderView::up-arrow { image: url("@icon_chevron_up"); width: 10px; height: 10px; subcontrol-position: center right; right: 4px; }
QHeaderView::down-arrow { image: url("@icon_chevron_down"); width: 10px; height: 10px; subcontrol-position: center right; right: 4px; }
QTableCornerButton::section { background-color: @surface; border: none; }

QScrollBar:vertical { background: transparent; width: 12px; margin: 3px 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px 3px; }
QScrollBar::handle:vertical { background-color: @fieldborder; border-radius: 4px; min-height: 32px; margin: 0 2px; }
QScrollBar::handle:horizontal { background-color: @fieldborder; border-radius: 4px; min-width: 32px; margin: 2px 0; }
QScrollBar::handle:hover { background-color: @muted; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QAbstractScrollArea::corner { background: transparent; border: none; }

QTabWidget::pane { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; top: -1px; }
QTabBar::tab { background: transparent; color: @muted; border: none; border-bottom: 2px solid transparent; padding: 8px 14px; font-weight: 600; }
QTabBar::tab:hover { color: @text; }
QTabBar::tab:selected { color: @primary; border-bottom: 2px solid @primary; }

QGroupBox { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; margin-top: 16px; padding: 10px 8px 8px 8px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 12px; padding: 0 4px; color: @muted; }

QProgressBar { background-color: @border; border: none; border-radius: 6px; text-align: center; color: @text; min-height: 14px; }
QProgressBar::chunk { background-color: @primary; border-radius: 6px; }

QSlider::groove:horizontal { height: 4px; background-color: @border; border-radius: 2px; }
QSlider::sub-page:horizontal { background-color: @primary; border-radius: 2px; }
QSlider::handle:horizontal { background-color: @primary; width: 16px; height: 16px; margin: -6px 0; border-radius: 8px; }

QFrame[frameShape="4"] { border: none; background-color: @border; min-height: 1px; max-height: 1px; }
QFrame[frameShape="5"] { border: none; background-color: @border; min-width: 1px; max-width: 1px; }
QComboBox QLineEdit, QAbstractSpinBox QLineEdit { border: none; background: transparent; padding: 0; }

QStatusBar { background-color: @page; border-top: 1px solid @border; color: @muted; }
QStatusBar::item { border: none; }
QStatusBar QLabel { color: @muted; }
QSplitter::handle { background-color: @border; }

/* Main window header (see neurai-qt NeuraiGUI::createToolBars). */
QFrame#headerCard { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; }
QLabel#headerTitle { color: @primary; font-size: 19px; font-weight: 700; }
QLabel#headerBalance { color: @text; font-size: 15px; font-weight: 700; }
QLabel#headerPrice { color: @muted; font-size: 11px; }
QLabel#networkChip { border-radius: 6px; padding: 2px 8px; font-size: 10px; font-weight: 700; }
QLabel#networkChip[mainnet="true"] { color: @success; background-color: @successbg; border: 1px solid @successborder; }
QLabel#networkChip[mainnet="false"] { color: @error; background-color: @errorbg; border: 1px solid @errorborder; }
QComboBox#headerCurrency { padding: 1px 22px 1px 6px; font-size: 11px; border-radius: 6px; }
QLabel#walletChip { border-radius: 6px; padding: 2px 8px; font-size: 10px; font-weight: 700; color: @muted; background-color: @surfalt; border: 1px solid @border; }
QToolBar#navBar { background: transparent; border: none; spacing: 2px; }
QToolBar#navBar QToolButton { color: @text; background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 5px 7px 4px 7px; font-size: 12px; font-weight: 500; }
QToolBar#navBar QToolButton:hover { color: @primary; }
QToolBar#navBar QToolButton:checked { color: @primary; border-bottom: 2px solid @primary; }
QToolBar#navBar QToolButton:disabled { color: @muted; }
QToolBar#navBar QToolButton[popupMode="2"] { padding-left: 16px; padding-right: 16px; }
QToolBar#navBar QToolButton::menu-indicator { image: url("@icon_chevron_down"); subcontrol-origin: padding; subcontrol-position: center right; width: 10px; height: 10px; right: 3px; }

/* Pages: Electrum's tab widget without its tab bar, on the page background. */
QTabWidget#mainTabs::pane { background: transparent; border: none; top: 0px; }
QWidget#overviewPage { background: transparent; }
QScrollArea#overviewScroll { background: transparent; border: none; }
QLabel#cardTitle { color: @text; font-size: 15px; font-weight: 600; }
QLabel#sectionTitle { color: @text; font-size: 14px; font-weight: 600; }
QLabel#cardCaption { color: @text; font-size: 13px; }
QLabel#cardValue { color: @text; font-size: 13px; }
QLabel#cardTotal { color: @text; font-size: 26px; font-weight: 700; }
QLabel#cardHint { color: @muted; font-size: 12px; }
QLabel#emptyHint { color: @muted; font-size: 13px; }
QListView#overviewList { background: transparent; border: none; }
/* Notice of the history: the addresses whose history is shown in part. */
QLabel#historyNotice { color: @text; background-color: @warnbg; border: 1px solid @warnborder; border-radius: 8px; padding: 7px 10px; }
QLineEdit#overviewSearch { padding: 3px 9px; }

/* Status bar buttons of Electrum (preferences, hardware wallet...). */
QStatusBar QToolButton { border-radius: 6px; padding: 2px; color: @muted; }
QStatusBar QToolButton:hover { color: @text; }
QStatusBar QPushButton:flat { color: @primary; }
'''


# Qt 5 reads a numeric CSS font-weight as weight / 8 on its 0..99 scale, so
# that 600 gives Bold instead of DemiBold. neurai-qt runs on Qt 6, which takes
# CSS weights as they are: convert to the Qt 5 values of the same weights.
_QT5_CSS_WEIGHTS = {100: 0, 200: 12, 300: 25, 400: 50, 500: 57, 600: 63, 700: 75, 800: 81, 900: 87}


def _qt5_font_weights(qss: str) -> str:
    import re
    from PyQt5.QtCore import QT_VERSION
    if QT_VERSION >= 0x060000:
        return qss

    def repl(m):
        weight = int(m.group(1))
        qt5 = _QT5_CSS_WEIGHTS.get(weight)
        return m.group(0) if qt5 is None else f'font-weight: {qt5 * 8}'
    return re.sub(r'font-weight:\s*(\d+)', repl, qss)


def build_stylesheet(t: Tokens, dark: bool) -> str:
    qss = _qt5_font_weights(STYLE_SHEET_TEMPLATE)
    primary_disabled = QColor('#7c4a2a') if dark else QColor('#fdba74')
    # Longer keys first so that no key is a prefix of one replaced later.
    replacements = (
        ('@icon_check', qss_url(icon_path('ui_check'))),
        ('@icon_chevron_down', qss_url(icon_path('ui_chevron_down'))),
        ('@icon_chevron_up', qss_url(icon_path('ui_chevron_up'))),
        ('@icon_chevron_right', qss_url(icon_path('ui_chevron_right_muted'))),
        ('@cardradiuspx', f'{CARD_RADIUS}px'),
        ('@fieldradiuspx', f'{FIELD_RADIUS}px'),
        ('@tooltiptext', css(t.page if dark else QColor('#ffffff'))),
        ('@tooltipbg', css(t.text if dark else QColor('#111827'))),
        ('@primdisabled', css(primary_disabled)),
        ('@successborder', css(with_alpha(t.success, 120))),
        ('@successbg', css(with_alpha(t.success, 36))),
        ('@errorborder', css(with_alpha(t.error, 120))),
        ('@warnborder', css(with_alpha(t.warning, 120))),
        ('@warnbg', css(with_alpha(t.warning, 36))),
        ('@errorbg', css(with_alpha(t.error, 36))),
        ('@fieldborder', css(t.field_border)),
        ('@primhover', css(t.primary_hover)),
        ('@primtext', css(t.primary_text)),
        ('@primary', css(t.primary)),
        ('@surfalt', css(t.surface_alt)),
        ('@surface', css(t.surface)),
        ('@border', css(t.border)),
        ('@accent', css(t.accent)),
        ('@success', css(t.success)),
        ('@error', css(t.error)),
        ('@muted', css(t.text_muted)),
        ('@page', css(t.page)),
        ('@text', css(t.text)),
    )
    for key, value in replacements:
        qss = qss.replace(key, value)
    return qss


_fonts_loaded = False


def load_fonts() -> bool:
    """Register the bundled Inter fonts. Returns whether the family is available."""
    global _fonts_loaded
    if not _fonts_loaded:
        _fonts_loaded = True
        for name in FONT_FILES:
            path = font_path(name)
            if QFontDatabase.addApplicationFont(path) < 0:
                _logger.warning(f'could not load font {path}')
    return FONT_FAMILY in QFontDatabase().families()


def apply(app: QApplication, dark: bool) -> None:
    """Install style, palette, font and style sheet on the application.
    Should run before the windows are created."""
    global _dark_mode
    _dark_mode = bool(dark)
    t = tokens()
    have_font = load_fonts()
    # On macOS neurai-qt keeps the system font, as it renders better there.
    if have_font and sys.platform != 'darwin':
        font = QApplication.font()
        font.setFamily(FONT_FAMILY)
        app.setFont(font)
    style = QStyleFactory.create('Fusion')
    if style is not None:
        app.setStyle(style)
    app.setPalette(make_palette(t, _dark_mode))
    app.setStyleSheet(build_stylesheet(t, _dark_mode))


def theme_font(weight: int = QFont.Normal, px: int = 13) -> QFont:
    """Font of neurai-qt's GUIUtil::makeThemeFont (getSubLabelFont & co.)."""
    font = QFont(QApplication.font())
    if sys.platform != 'darwin':
        font.setFamily(FONT_FAMILY)
    font.setWeight(weight)
    font.setPixelSize(px)
    return font


def make_card(widget: QWidget, extra_rules: str = '') -> None:
    """Turn a container into a card: surface colour, border and rounded corners.
    The rule targets the widget by object name so that child frames such as
    separator lines are left untouched."""
    if not widget.objectName():
        widget.setObjectName(f'card{id(widget):x}')
    widget.setAttribute(Qt.WA_StyledBackground, True)
    t = tokens()
    widget.setStyleSheet(
        f'#{widget.objectName()} {{ background-color: {css(t.surface)}; border: 1px solid {css(t.border)}; '
        f'border-radius: {CARD_RADIUS}px; {extra_rules} }}')


def shadow_effect() -> Optional[QGraphicsDropShadowEffect]:
    """The soft shadow of neurai-qt's cards (GUIUtil::getShadowEffect); None on macOS."""
    if sys.platform == 'darwin':
        return None
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(28)
    shadow.setColor(tokens().shadow)
    shadow.setOffset(0, 4)
    return shadow


def add_shadow(widget: QWidget) -> None:
    effect = shadow_effect()
    if effect is not None:
        widget.setGraphicsEffect(effect)


def colorize_image(source: Union[str, QImage], color: QColor) -> QImage:
    """Single-colour version of an image: every pixel gets the colour, the alpha is kept."""
    img = QImage(source) if isinstance(source, str) else QImage(source)
    img = img.convertToFormat(QImage.Format_ARGB32_Premultiplied)
    painter = QPainter(img)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(img.rect(), QColor(color))
    painter.end()
    return img


def single_color_icon(source: Union[str, QIcon], color: QColor) -> QIcon:
    if isinstance(source, QIcon):
        icon = QIcon()
        for size in source.availableSizes() or [QSize(48, 48)]:
            icon.addPixmap(QPixmap.fromImage(colorize_image(source.pixmap(size).toImage(), color)))
        return icon
    return QIcon(QPixmap.fromImage(colorize_image(source, color)))


def neurai_icon(name: str, color: QColor = None) -> QIcon:
    """An icon from electrum/gui/icons/neurai, tinted with the text colour by default."""
    return single_color_icon(icon_path(name), color if color is not None else tokens().text)


def navigation_icon(name: str) -> QIcon:
    """Icon of a navigation entry (PlatformStyle::NavigationIcon): text colour
    when idle, accent when checked or hovered, muted when disabled."""
    t = tokens()
    path = icon_path(name)
    idle = QPixmap.fromImage(colorize_image(path, t.text))
    active = QPixmap.fromImage(colorize_image(path, t.primary))
    disabled = QPixmap.fromImage(colorize_image(path, t.text_muted))
    icon = QIcon()
    icon.addPixmap(idle, QIcon.Normal, QIcon.Off)
    icon.addPixmap(active, QIcon.Normal, QIcon.On)
    icon.addPixmap(active, QIcon.Active, QIcon.Off)
    icon.addPixmap(active, QIcon.Active, QIcon.On)
    icon.addPixmap(disabled, QIcon.Disabled, QIcon.Off)
    icon.addPixmap(disabled, QIcon.Disabled, QIcon.On)
    return icon


def make_transparent_scroll_area(scroll) -> None:
    """A scroll area without frame that shows the card or page it is on."""
    from PyQt5.QtWidgets import QFrame
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.viewport().setAutoFillBackground(False)
    widget = scroll.widget()
    if widget is not None:
        widget.setAutoFillBackground(False)
    scroll.setStyleSheet('QScrollArea { background: transparent; border: none; }'
                         ' QScrollArea > QWidget > QWidget { background: transparent; }')


# Electrum icons drawn with the single-colour icons of neurai-qt instead,
# tinted with the colour of their meaning (see util.read_QIcon).
THEMED_ICONS = {
    'confirmed.png': ('transaction2', 'success'),
    'unconfirmed.png': ('transaction0', 'text_muted'),
    'clock1.png': ('clock1', 'text_muted'),
    'clock2.png': ('clock2', 'text_muted'),
    'clock3.png': ('clock3', 'text_muted'),
    'clock4.png': ('clock4', 'text_muted'),
    'clock5.png': ('clock5', 'text_muted'),
    'offline_tx.png': ('debugwindow', 'warning'),
    'warning.png': ('warning', 'warning'),
    'expired.png': ('transaction_conflicted', 'error'),
    'unpaid.png': ('nav_history', 'warning'),
    'copy.png': ('ui_copy', 'text_muted'),
    'preferences.png': ('nav_settings', 'text_muted'),
    'eye1.png': ('nav_eye', 'text_muted'),
}


def themed_icon(icon_basename: str) -> Optional[QIcon]:
    entry = THEMED_ICONS.get(icon_basename)
    if entry is None or QApplication.instance() is None:
        return None  # pixmaps need the application
    name, token = entry
    return neurai_icon(name, getattr(tokens(), token))


# Big illustrations of Electrum (dialogs and wizard pages), drawn with the
# single-colour icons of neurai-qt in the accent colour
ACCENT_PIXMAPS = {
    'lock.png': 'status_lock',
    'unlock.png': 'status_unlock',
    'seed.png': 'nav_seed',
}


def accent_pixmap(icon_basename: str, size: int) -> QPixmap:
    name = ACCENT_PIXMAPS.get(icon_basename)
    if name is None:
        return QPixmap(resource_path('gui', 'icons', icon_basename)).scaledToWidth(
            size, mode=Qt.SmoothTransformation)
    icon = neurai_icon(name, tokens().primary)
    return icon.pixmap(QSize(size, size))


def grid_line_color() -> QColor:
    """Colour of the grid lines of tables and lists (gridline-color of neurai-qt)."""
    return QColor(tokens().border)


def make_primary(button) -> None:
    """The main action of a page or dialog: orange, as the primary buttons of neurai-qt."""
    if button.property('primary') is not True:
        button.setProperty('primary', True)
        style = button.style()
        style.unpolish(button)
        style.polish(button)


def mark_compact(button) -> None:
    """Small padding for a button of fixed size (icon-only or one character),
    which the padding of the theme would clip."""
    if button.property('compact') is not True:
        button.setProperty('compact', True)
        style = button.style()
        style.unpolish(button)
        style.polish(button)


class _CompactButtonWatcher(QObject):
    """Marks compact the push buttons added to a widget (e.g. by plugins) that
    have a fixed size smaller than the padding of the theme needs."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.ChildPolished:
            child = event.child()
            if isinstance(child, QPushButton) and child.property('compact') is not True:
                hint = child.sizeHint()
                if child.maximumWidth() < hint.width() or child.maximumHeight() < hint.height():
                    mark_compact(child)
        return False


def watch_compact_buttons(widget: QWidget) -> None:
    watcher = _CompactButtonWatcher(widget)
    widget.installEventFilter(watcher)
    widget._compact_button_watcher = watcher


def menu_icon() -> QIcon:
    """Icon of the option menus of the lists and pages (Electrum's toolbar menus)."""
    return neurai_icon('nav_settings', tokens().text_muted)


def make_page_card(title_layout=None, *, shadow: bool = True, margins=(16, 14, 16, 14)):
    """A card for a section of a page, with the toolbar layout of the section
    (title label on the left, option menu on the right) on top. Returns the
    card and its vertical layout."""
    from PyQt5.QtWidgets import QFrame, QVBoxLayout, QLabel
    card = QFrame()
    card.setFrameShape(QFrame.NoFrame)
    make_card(card)
    if shadow:
        add_shadow(card)
    vbox = QVBoxLayout(card)
    vbox.setContentsMargins(*margins)
    vbox.setSpacing(10)
    if title_layout is not None:
        for i in range(title_layout.count()):
            w = title_layout.itemAt(i).widget()
            if isinstance(w, QLabel):
                w.setObjectName('cardTitle')
                break
        vbox.addLayout(title_layout)
    return card, vbox


def badge_tint(color: QColor, hover: bool = False) -> QColor:
    """Background of a status badge tinted with its icon colour."""
    if hover:
        return with_alpha(color, 96 if _dark_mode else 60)
    return with_alpha(color, 56 if _dark_mode else 30)
