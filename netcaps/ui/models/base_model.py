"""Base table model for all NetCaps table views."""

try:
    from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex
    from PySide6.QtGui import QColor
    HAS_QT = True
except ImportError:
    HAS_QT = False


if HAS_QT:
    class BaseTableModel(QAbstractTableModel):
        HEADERS = []

        def __init__(self, parent=None):
            super().__init__(parent)
            self._rows = []
            self._filtered_rows = []
            self._filter_text = ""

        def rowCount(self, parent=QModelIndex()):
            return len(self._filtered_rows)

        def columnCount(self, parent=QModelIndex()):
            return len(self.HEADERS)

        def headerData(self, section, orientation, role=Qt.DisplayRole):
            if role == Qt.DisplayRole and orientation == Qt.Horizontal:
                if 0 <= section < len(self.HEADERS):
                    return self.HEADERS[section]
            return None

        def data(self, index, role=Qt.DisplayRole):
            if not index.isValid():
                return None
            row = self._filtered_rows[index.row()]
            if role == Qt.DisplayRole:
                values = self.row_to_display(row)
                col = index.column()
                if 0 <= col < len(values):
                    return str(values[col]) if values[col] is not None else ""
            return None

        def row_to_display(self, row):
            """Override in subclass. Return list of values for display."""
            return []

        def setData(self, rows):
            self.beginResetModel()
            self._rows = list(rows)
            self._apply_filter()
            self.endResetModel()

        def filterByText(self, text: str):
            self._filter_text = text.lower()
            self.beginResetModel()
            self._apply_filter()
            self.endResetModel()

        def _apply_filter(self):
            if not self._filter_text:
                self._filtered_rows = list(self._rows)
            else:
                words = self._filter_text.split()
                result = []
                for row in self._rows:
                    s = getattr(row, "search_str", "") or ""
                    if all(w in s for w in words):
                        result.append(row)
                self._filtered_rows = result

        def sort(self, column: int, order=Qt.AscendingOrder):
            if not self._filtered_rows:
                return
            reverse = order == Qt.DescendingOrder
            try:
                self.beginResetModel()
                self._filtered_rows.sort(
                    key=lambda row: (self.row_to_display(row)[column] or ""),
                    reverse=reverse,
                )
                self.endResetModel()
            except Exception:
                pass

        def getRow(self, index):
            """Return underlying data row for a model index."""
            if index.isValid() and 0 <= index.row() < len(self._filtered_rows):
                return self._filtered_rows[index.row()]
            return None

        def getCellValue(self, index):
            """Return display string for a cell."""
            row = self.getRow(index)
            if row is None:
                return ""
            values = self.row_to_display(row)
            col = index.column()
            if 0 <= col < len(values):
                return str(values[col]) if values[col] is not None else ""
            return ""

else:
    class BaseTableModel:
        HEADERS = []

        def __init__(self, parent=None):
            self._rows = []
            self._filtered_rows = []
            self._filter_text = ""

        def setData(self, rows):
            self._rows = list(rows)
            self._apply_filter()

        def filterByText(self, text: str):
            self._filter_text = text.lower()
            self._apply_filter()

        def _apply_filter(self):
            if not self._filter_text:
                self._filtered_rows = list(self._rows)
            else:
                words = self._filter_text.split()
                self._filtered_rows = [
                    r for r in self._rows
                    if all(w in (getattr(r, "search_str", "") or "") for w in words)
                ]
