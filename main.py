import sys
from PySide6.QtWidgets import QApplication
from ui_backend import UiBackend
if __name__ == "__main__":
    app = QApplication()
    ui = UiBackend()
    ui.show()
    sys.exit(app.exec())
