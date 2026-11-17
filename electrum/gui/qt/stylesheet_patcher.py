"""This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets


# Fixes for Electrum widgets on top of the Neurai theme (neurai_theme.py),
# which styles both the light and the dark variant.
CUSTOM_PATCH = '''
/* In History tab, labels while edited were being clipped */
QAbstractItemView QLineEdit {
    padding: 0px;
    border-radius: 4px;
    show-decoration-selected: 1;
}
/* Checked item in dropdowns have way too much height... see #6281 */
QComboBox::item:checked {
    font-weight: bold;
    max-height: 30px;
}
'''


def patch_qt_stylesheet(use_dark_theme: bool) -> None:
    app = QtWidgets.QApplication.instance()
    style_sheet = app.styleSheet() + CUSTOM_PATCH
    app.setStyleSheet(style_sheet)
