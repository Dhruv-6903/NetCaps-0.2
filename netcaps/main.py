"""NetCaps application entry point."""

import sys
import os


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
    except ImportError:
        print("Error: PySide6 is not installed. Run: pip install PySide6", file=sys.stderr)
        return 1

    # High-DPI support
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("NetCaps")
    app.setApplicationVersion("0.2.0")
    app.setOrganizationName("NetCaps")

    try:
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    except AttributeError:
        pass

    from netcaps.ui.main_window import MainWindow
    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
