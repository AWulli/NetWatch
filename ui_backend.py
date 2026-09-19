from pathlib import Path
import subprocess as sp

from PySide6.QtCore import Qt, QIODevice, QFile, QModelIndex, QTime
from PySide6.QtWidgets import QMainWindow, QPushButton, QPlainTextEdit, QTableView, QHeaderView 
from PySide6.QtUiTools import QUiLoader
from PySide6.QtGui import QStandardItem, QStandardItemModel

from classes.firewall_status import Firewall
from classes.portscanner import PortScanner
from classes.portscanner import SocketData

class UiBackend(QMainWindow):
    def __init__(self):
        super().__init__()

        self.ui_filepath: Path = Path(__file__).parent / "../ui/netwatch_main.ui"
        
        self.setWindowTitle("NET_WATCH")
        self.resize(900,800)


        loader = QUiLoader()
        ui_file: QFile = QFile(self.ui_filepath)
        ui_file.open(QIODevice.OpenModeFlag.ReadOnly)
        self.ui = loader.load(ui_file, self)
        ui_file.close()
        self.ui.show()

        self.check_ufw_button = self.ui.findChild(QPushButton, "checkUFWButton")
        self.ufw_status_output = self.ui.findChild(QPlainTextEdit, "checkUFWOutputBox")
        self.connection_table = self.ui.findChild(QTableView, "tableView")
        self.scan_ports_button = self.ui.findChild(QPushButton, "scanPortsButton")
        self.whois_button = self.ui.findChild(QPushButton, "whoisButton")
        self.whois_output_box = self.ui.findChild(QPlainTextEdit, "whoisPlainTextEdit")

        self.connection_table_model = QStandardItemModel()
        self.connection_table_model.setHorizontalHeaderLabels(["Protocoll", "local IP", "local Port", "remote IP", "remote Port", "Status", "Role", "PID", "Process"])
        self.connection_table.setModel(self.connection_table_model)
        header = self.connection_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)

        self.check_ufw_button.clicked.connect(self.check_ufw_status) #erneutes Abfragen zur Laufzeit
        self.scan_ports_button.clicked.connect(self.show_ports_scan)
        self.whois_button.clicked.connect(self.whois_this)

        #Damit die Abfragen direkt beim Start des Programms passieren und nicht extra dazu aufgefordert werden muss:
        self.check_ufw_status()
        self.show_ports_scan()

        
            
    def check_ufw_status(self) -> None:
        firewall = Firewall()
        firewallstatus = firewall.get_status_verbose()
        if not firewallstatus:
            self.ufw_status_output.setPlainText("Could not get Information!\nMaybe you have to run the Prog with 'sudo'...")
        else:
            self.ufw_status_output.setPlainText(firewallstatus)
    
    
    def show_ports_scan(self) -> None:
        portscanner = PortScanner()
        self.connection_table_model.removeRows(0, self.connection_table_model.rowCount())
        for socketinfo in portscanner.socketinfos:
            protocoll_item = QStandardItem(socketinfo.protocol)
            protocoll_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            local_ip_item = QStandardItem(socketinfo.local_ip)
            local_ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            local_port_item = QStandardItem(socketinfo.local_port)
            local_port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            remote_ip_item = QStandardItem(socketinfo.remote_ip)
            remote_ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            remote_port_item = QStandardItem(socketinfo.remote_port)
            remote_port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item = QStandardItem(socketinfo.status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            role_item = QStandardItem(socketinfo.role)
            role_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pid_item = QStandardItem(socketinfo.pid)
            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            process_item = QStandardItem(socketinfo.process)
            process_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.connection_table_model.appendRow([protocoll_item, local_ip_item, local_port_item, remote_ip_item, remote_port_item, status_item, role_item, pid_item, process_item])
    

    def whois_this(self) -> None:
        index = self.connection_table.currentIndex()

        if index.isValid():
            cmd = f"whois {index.data()}"
            cmd_run = sp.run([cmd], shell=True, text=True, capture_output=True)
            self.whois_output_box.setPlainText(cmd_run.stdout)
        else:
            self.whois_output_box.setPlainText("Please choose a 'remote IP', you want to check!")

