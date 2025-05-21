import sys
import os
from PyQt5.QtWidgets import QApplication
from gui_app import MainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())