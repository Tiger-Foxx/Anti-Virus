import os, gc, sys, time, json
import ctypes, ctypes.wintypes
import requests, msvcrt, pyperclip
from Foxy_Engine import YRScan, DLScan
from PYAS_Suffixes import file_types

from Foxy_Interface import Ui_MainWindow
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from subprocess import *
from threading import *

class PROCESSENTRY32(ctypes.Structure): 
    _fields_ = [
    ("dwSize", ctypes.wintypes.DWORD),
    ("cntUsage", ctypes.wintypes.DWORD),
    ("th32ProcessID", ctypes.wintypes.DWORD),
    ("th32DefaultHeapID", ctypes.wintypes.LPVOID),
    ("th32ModuleID", ctypes.wintypes.DWORD),
    ("cntThreads", ctypes.wintypes.DWORD),
    ("th32ParentProcessID", ctypes.wintypes.DWORD),
    ("dwFlags", ctypes.wintypes.DWORD),
    ("szExeFile", ctypes.wintypes.CHAR * 260)]

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
    ("dwState", ctypes.wintypes.DWORD),
    ("dwLocalAddr", ctypes.wintypes.DWORD),
    ("dwLocalPort", ctypes.wintypes.DWORD),
    ("dwRemoteAddr", ctypes.wintypes.DWORD),
    ("dwRemotePort", ctypes.wintypes.DWORD),
    ("dwOwningPid", ctypes.wintypes.DWORD)]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
    ("dwNumEntries", ctypes.wintypes.DWORD),
    ("table", MIB_TCPROW_OWNER_PID * 1)]

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
    ("NextEntryOffset", ctypes.wintypes.DWORD),
    ("Action", ctypes.wintypes.DWORD),
    ("FileNameLength", ctypes.wintypes.DWORD),
    ("FileName", ctypes.wintypes.WCHAR * 1024)]

class MainWindow_Controller(QMainWindow): 
    def __init__(self): 
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.init_config_pyas() 

    def init_config_pyas(self):
        self.init_config_vars() 
        self.init_config_path() 
        self.init_config_read() 
        self.init_config_wdll() 
        self.init_config_boot() 
        self.init_config_list() 
        self.init_config_data() 
        self.init_config_icon() 
        self.init_config_qtui() 
        self.init_config_color() 
        self.init_config_conn() 
        self.init_config_lang() 
        self.init_config_func() 
        self.init_config_done() 
        self.init_config_theme() 

    def init_config_vars(self): 
        self.pyae_version = "AI Engine"
        self.pyas_version = "3.3.0"
        self.mbr_value = None
        self.track_proc = None
        self.first_startup = 1
        self.pyas_opacity = 0
        self.gc_collect = 0
        self.block_window = 0
        self.total_scan = 0
        self.scan_time = 0
        self.virus_lock = {}
        self.virus_list_ui = []
        self.Process_quantity = 0
        self.Process_list_all_pid = []
        self.default_json = {
        "language_ui": "en_US",  
        "theme_color": "White",  
        "product_key": "None",   
        "service_url": "None",   
        "proc_protect": 1, 
        "file_protect": 1, 
        "sys_protect": 1,  
        "net_protect": 1,  
        "cus_protect": 0,  
        "sensitivity": 0,  
        "extend_mode": 0,  
        "white_lists": [], 
        "block_lists": []  
        }
        self.pass_windows = [ 
        {'': ''}, {'PYAS': 'Qt5152QWindowIcon'},
        {'': 'Shell_TrayWnd'}, {'': 'WorkerW'}]

    def init_config_path(self): 
        try:
            self.path_conf = r"C:/ProgramData/PYAS"
            self.path_pyas = sys.argv[0].replace("\\", "/")
            self.path_dirs = os.path.dirname(self.path_pyas)
            self.file_conf = os.path.join(self.path_conf, "PYAS.json")
            self.path_model = os.path.join(self.path_dirs, "Engine/Model")
            self.path_rules = os.path.join(self.path_dirs, "Engine/Rules")
            self.path_driver = os.path.join(self.path_dirs, "Driver/Protect")
        except Exception as e:
            print(e)

    def reset_options(self): 
        if self.question_event("Are you sure you want to reset all settings?"):
            self.clean_function()
            self.config_json = self.default_json
            self.init_config_write(self.config_json)
            self.init_config_pyas()

    def clean_function(self): 
        self.first_startup = 1
        self.block_window = 0
        self.config_json["proc_protect"] = 0
        self.config_json["file_protect"] = 0
        self.config_json["sys_protect"] = 0
        self.config_json["net_protect"] = 0
        self.virus_scan_break()
        self.protect_drv_init(stop_only=True) 
        self.gc_collect = 0

    def init_config_read(self): 
        try:
            self.config_json = {}
            if not os.path.exists(self.path_conf):
                os.makedirs(self.path_conf)
            if not os.path.exists(self.file_conf):
                 
                self.config_json = self.default_json.copy()
                self.init_config_write(self.config_json)
            else:
                with open(self.file_conf, "r") as f:
                    self.config_json = json.load(f)

            
            for key, default_value in self.default_json.items():
                self.config_json[key] = self.config_json.get(key, default_value)

        except Exception as e:
            print(f"Error reading config: {e}")
            
            self.config_json = self.default_json.copy()
            self.init_config_write(self.config_json)


    def init_config_write(self, config): 
        try:
            with open(self.file_conf, "w") as f:
                
                f.write(json.dumps(config, indent=4, ensure_ascii=True))
        except Exception as e:
            print(e)

    def init_config_wdll(self): 
        try:
            self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            self.psapi = ctypes.WinDLL('Psapi', use_last_error=True)
            self.user32 = ctypes.WinDLL('user32', use_last_error=True)
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            self.iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
        except Exception as e:
            print(e)

    def init_config_boot(self): 
        try:
            
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                self.mbr_value = f.read(512)
            
            if self.mbr_value[510:512] != b'\x55\xAA':
                self.mbr_value = None 
        except PermissionError:
            print("Permission denied reading PhysicalDrive0. Run as Administrator.")
            self.mbr_value = None
        except Exception as e:
            print(f"Error reading MBR: {e}")
            self.mbr_value = None

    def init_config_list(self): 
        try:
            self.exist_process = self.get_process_list()
            self.exist_connections = self.get_connections_list()
        except Exception as e:
            print(e)

    def init_config_data(self): 
        try:
            self.model = DLScan()
            for root, dirs, files in os.walk(self.path_model):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.model.load_model(file_path)
        except Exception as e:
            print(f"Error loading DL models: {e}")
        try:
            self.rules = YRScan()
            for root, dirs, files in os.walk(self.path_rules):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.rules.load_rules(file_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")

    def init_config_icon(self): 
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.activated.connect(self.init_config_show)
        
        self.tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(self.path_pyas)))
        self.tray_icon.show()

    def init_config_qtui(self): 
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.Process_sim = QStringListModel()
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.process_list)

        
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()

        
        self.effect_shadow = QGraphicsDropShadowEffect(self)
        self.effect_shadow.setOffset(0,0)
        self.effect_shadow.setBlurRadius(10)
        self.effect_shadow.setColor(Qt.gray)
        self.ui.widget_2.setGraphicsEffect(self.effect_shadow)

        self.effect_shadow2 = QGraphicsDropShadowEffect(self)
        self.effect_shadow2.setOffset(0,0)
        self.effect_shadow2.setBlurRadius(10)
        self.effect_shadow2.setColor(Qt.gray)
        self.ui.Navigation_Bar.setGraphicsEffect(self.effect_shadow2)

        self.effect_shadow3 = QGraphicsDropShadowEffect(self)
        self.effect_shadow3.setOffset(0,0)
        self.effect_shadow3.setBlurRadius(7)
        self.effect_shadow3.setColor(Qt.gray)
        self.ui.Window_widget.setGraphicsEffect(self.effect_shadow3)

        
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_widget.hide()
        self.ui.Tools_widget.hide()
        self.ui.Protection_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Process_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()

        
        self.ui.State_output.style().polish(self.ui.State_output.verticalScrollBar())
        self.ui.Virus_Scan_output.style().polish(self.ui.Virus_Scan_output.verticalScrollBar())

        
        self.ui.License_terms.setText('''MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')

    def init_config_conn(self): 
        
        self.ui.Close_Button.clicked.connect(self.close)
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.show_menu) 

        
        self.ui.State_Button.clicked.connect(self.change_state_widget)
        self.ui.Tools_Button.clicked.connect(self.change_tools_widget)
        self.ui.Virus_Scan_Button.clicked.connect(self.change_scan_widget)
        self.ui.Protection_Button.clicked.connect(self.change_protect_widget)
        self.ui.Setting_Button.clicked.connect(self.change_setting_widget)

        
        self.ui.Virus_Scan_output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Virus_Scan_output.customContextMenuRequested.connect(self.Virus_Scan_output_menu)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)

        
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.change_tools(self.ui.Process_widget))
        self.ui.Repair_System_Files_Button.clicked.connect(self.repair_system)
        self.ui.Clean_System_Files_Button.clicked.connect(self.clean_system)
        self.ui.Window_Block_Button.clicked.connect(self.add_software_window)
        self.ui.Window_Block_Button_2.clicked.connect(self.remove_software_window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.repair_network)
        self.ui.Reset_Options_Button.clicked.connect(self.reset_options)

        
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.process_list_menu)

        
        self.ui.Protection_switch_Button.clicked.connect(self.protect_proc_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_file_init)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_sys_init)
        self.ui.Protection_switch_Button_4.clicked.connect(lambda: self.protect_drv_init(stop_only=False)) 
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_net_init)
        self.ui.Protection_switch_Button_8.clicked.connect(self.protect_cus_init)

        
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.change_sensitive)
        self.ui.extension_kit_switch_Button.clicked.connect(self.extension_kit)
        self.ui.cloud_services_switch_Button.clicked.connect(self.cloud_services)

        
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Add_White_list_Button_3.clicked.connect(self.remove_white_list)

        
        self.ui.Language_Traditional_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_English.clicked.connect(self.init_change_lang)

        
        self.ui.Theme_White.clicked.connect(self.init_change_theme)
        self.ui.Theme_Customize.clicked.connect(self.init_change_theme)
        self.ui.Theme_Green.clicked.connect(self.init_change_theme)
        self.ui.Theme_Yellow.clicked.connect(self.init_change_theme)
        self.ui.Theme_Blue.clicked.connect(self.init_change_theme)
        self.ui.Theme_Red.clicked.connect(self.init_change_theme)

    def init_config_lang(self): 
        try:
            
            lang = self.config_json.get("language_ui", "en_US")
            if lang == "zh_TW":
                self.ui.Language_Traditional_Chinese.setChecked(True)
            elif lang == "zh_CN":
                self.ui.Language_Simplified_Chinese.setChecked(True)
            else: 
                self.ui.Language_English.setChecked(True)
            self.init_change_text() 
        except Exception as e:
            print(e)

    def init_change_lang(self): 
        try:
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_TW"
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_CN"
            elif self.ui.Language_English.isChecked():
                self.config_json["language_ui"] = "en_US"
            
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    

    def init_change_text(self): 
        
        self.ui.State_title.setText("This device is protected")
        self.ui.State_log.setText("Log:")

        
        self.ui.Window_title.setText("Foxy Security")
        self.ui.PYAS_CopyRight.setText(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} Foxy Security")

        
        self.ui.Virus_Scan_title.setText("Virus Scan")
        self.ui.Virus_Scan_text.setText("Please select a scan method")
        self.ui.Virus_Scan_choose_Button.setText("Virus Scan") 
        self.ui.File_Scan_Button.setText("File Scan")
        self.ui.Path_Scan_Button.setText("Path Scan")
        self.ui.Disk_Scan_Button.setText("Full Scan")
        self.ui.Virus_Scan_Solve_Button.setText("Delete Now")
        self.ui.Virus_Scan_Break_Button.setText("Stop Scan")

        
        self.ui.Process_Total_title.setText("Total Processes:")
        

        
        
        self.ui.Protection_title.setText("Process Protection")
        self.ui.Protection_illustrate.setText("Enable this option to intercept process viruses")
        
        self.ui.Protection_switch_Button.setText("Disabled") 

        
        self.ui.Protection_title_2.setText("File Protection")
        self.ui.Protection_illustrate_2.setText("Enable this option to monitor file changes")
        self.ui.Protection_switch_Button_2.setText("Disabled")

        
        self.ui.Protection_title_3.setText("System Protection")
        self.ui.Protection_illustrate_3.setText("Enable this option to repair system items")
        self.ui.Protection_switch_Button_3.setText("Disabled")

        
        self.ui.Protection_title_4.setText("Driver Protection")
        self.ui.Protection_illustrate_4.setText("Enable this option to enhance self-protection")
        self.ui.Protection_switch_Button_4.setText("Disabled")

        
        self.ui.Protection_title_5.setText("Network Protection")
        self.ui.Protection_illustrate_5.setText("Enable this option to monitor network communications")
        self.ui.Protection_switch_Button_5.setText("Disabled")

        
        self.ui.Protection_title_8.setText("Custom Protection")
        self.ui.Protection_illustrate_8.setText("Enable this option to select custom protection")
        self.ui.Protection_switch_Button_8.setText("Disabled")

        
        
        self.ui.System_Process_Manage_title.setText("Process Management")
        self.ui.System_Process_Manage_illustrate.setText("This option allows real-time viewing of system processes")
        self.ui.System_Process_Manage_Button.setText("Select")

        
        self.ui.Clean_System_Files_title.setText("Junk Clean")
        self.ui.Clean_System_Files_illustrate.setText("This option can clean temporary files")
        self.ui.Clean_System_Files_Button.setText("Select")

        
        self.ui.Repair_System_Files_title.setText("System Repair")
        self.ui.Repair_System_Files_illustrate.setText("This option can repair system registry entries")
        self.ui.Repair_System_Files_Button.setText("Select")

        
        self.ui.Repair_System_Network_title.setText("Network Repair")
        self.ui.Repair_System_Network_illustrate.setText("This option can reset system network connections")
        self.ui.Repair_System_Network_Button.setText("Select")

        
        self.ui.Reset_Options_title.setText("Reset Options")
        self.ui.Reset_Options_illustrate.setText("This option can reset all setting options")
        self.ui.Reset_Options_Button.setText("Select")

        
        self.ui.Window_Block_title.setText("Popup Blocking")
        self.ui.Window_Block_illustrate.setText("This option allows selecting specific windows to block")
        self.ui.Window_Block_Button.setText("Add")
        self.ui.Window_Block_Button_2.setText("Remove")

        
        self.ui.PYAS_Version.setText(f"Foxy Security V{self.pyas_version} ({self.pyae_version})")
        self.ui.GUI_Made_title.setText("Interface Design:")
        self.ui.GUI_Made_Name.setText("mtkiao")
        self.ui.Core_Made_title.setText("Core Development:")
        self.ui.Core_Made_Name.setText("87owo")
        self.ui.Testers_title.setText("Special Thanks:")
        self.ui.Testers_Name.setText("0sha0") 
        self.ui.PYAS_URL_title.setText("Official Website:")
        self.ui.PYAS_URL.setText("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline;\">")
        self.ui.License_terms_title.setText("License Terms:")

        
        
        self.ui.high_sensitivity_title.setText("High Sensitivity Mode")
        self.ui.high_sensitivity_illustrate.setText("Enable this option to increase scan engine sensitivity")
        self.ui.high_sensitivity_switch_Button.setText("Disabled") 

        
        self.ui.extension_kit_title.setText("Extended Scan Engine")
        self.ui.extension_kit_illustrate.setText("Enable this option to use third-party extension kits")
        self.ui.extension_kit_switch_Button.setText("Disabled")

        
        self.ui.cloud_services_title.setText("Cloud Scan Service")
        self.ui.cloud_services_illustrate.setText("Enable this option to connect to cloud scanning services")
        self.ui.cloud_services_switch_Button.setText("Disabled")

        
        self.ui.Add_White_list_title.setText("Add to Whitelist")
        self.ui.Add_White_list_illustrate.setText("This option allows selecting files/folders to add to the whitelist")
        self.ui.Add_White_list_Button.setText("Add")
        self.ui.Add_White_list_Button_3.setText("Remove")

        
        self.ui.Theme_title.setText("Display Theme")
        self.ui.Theme_illustrate.setText("Please select a theme")
        self.ui.Theme_Customize.setText("Custom Theme")
        self.ui.Theme_White.setText("White Theme")
        self.ui.Theme_Yellow.setText("Yellow Theme")
        self.ui.Theme_Red.setText("Red Theme")
        self.ui.Theme_Green.setText("Green Theme")
        self.ui.Theme_Blue.setText("Blue Theme")

        
        self.ui.Language_title.setText("Display Language")
        self.ui.Language_illustrate.setText("Please select a language")
        
        
        
        

        
        self._update_button_texts_from_config()


    def _update_button_texts_from_config(self):
        """Helper to set initial button texts based on config values."""
        self.ui.Protection_switch_Button.setText("Enabled" if self.config_json.get("proc_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_2.setText("Enabled" if self.config_json.get("file_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_3.setText("Enabled" if self.config_json.get("sys_protect", 0) else "Disabled")
        
        self.ui.Protection_switch_Button_5.setText("Enabled" if self.config_json.get("net_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_8.setText("Enabled" if self.config_json.get("cus_protect", 0) else "Disabled")
        self.ui.high_sensitivity_switch_Button.setText("Enabled" if self.config_json.get("sensitivity", 0) else "Disabled")
        self.ui.extension_kit_switch_Button.setText("Enabled" if self.config_json.get("extend_mode", 0) else "Disabled")
        self.ui.cloud_services_switch_Button.setText("Enabled" if self.config_json.get("service_url", "None") != "None" else "Disabled") 


    def init_config_color(self): 
        self.config_theme = {
        "White": {"color": "White", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(230,230,230);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(220,220,220);}""",
        "widget_style": "background-color:rgb(255,255,255);",
        "window_style": "background-color:rgb(245,245,245);",
        "navigation_style": "background-color:rgb(235,235,235);"},
        "Red": {"color": "Red", "icon": ":/icon/Check.png", 
        "button_on": """QPushButton{border:none;
        background-color:rgb(250,200,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,210,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(250,220,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,210,210);}""",
        "widget_style": "background-color:rgb(250,240,240);",
        "window_style": "background-color:rgb(250,230,230);",
        "navigation_style": "background-color:rgb(250,220,220);"},
        "Green": {"color": "Green", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(220,250,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "widget_style": "background-color:rgb(240,250,240);",
        "window_style": "background-color:rgb(230,250,230);",
        "navigation_style": "background-color:rgb(220,250,220);"},
        "Blue": {"color": "Blue", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,250);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,250);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(220,250,250);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,250);}""",
        "widget_style": "background-color:rgb(240,250,250);",
        "window_style": "background-color:rgb(230,250,250);",
        "navigation_style": "background-color:rgb(220,250,250);"},
        "Yellow": {"color": "Yellow", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(250,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(250,250,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,250,210);}""",
        "widget_style": "background-color:rgb(250,250,240);",
        "window_style": "background-color:rgb(250,250,230);",
        "navigation_style": "background-color:rgb(250,250,220);"}}
        
        

    def init_config_theme(self): 
        try:
            theme_name = self.config_json.get("theme_color", "White")
            if theme_name == "White":
                self.ui.Theme_White.setChecked(True)
            elif theme_name == "Red":
                self.ui.Theme_Red.setChecked(True)
            elif theme_name == "Green":
                self.ui.Theme_Green.setChecked(True)
            elif theme_name == "Yellow":
                self.ui.Theme_Yellow.setChecked(True)
            elif theme_name == "Blue":
                self.ui.Theme_Blue.setChecked(True)
            elif os.path.exists(theme_name): 
                 self.ui.Theme_Customize.setChecked(True)
            else: 
                self.config_json["theme_color"] = "White"
                self.ui.Theme_White.setChecked(True)

            self.init_change_color() 
        except Exception as e:
            print(f"Error initializing theme UI: {e}")
            self.config_json["theme_color"] = "White" 
            self.ui.Theme_White.setChecked(True)
            self.init_change_color()


    def init_change_theme(self): 
        try:
            new_theme_value = "White" 
            if self.ui.Theme_White.isChecked():
                new_theme_value = "White"
            elif self.ui.Theme_Red.isChecked():
                new_theme_value = "Red"
            elif self.ui.Theme_Green.isChecked():
                new_theme_value = "Green"
            elif self.ui.Theme_Blue.isChecked():
                new_theme_value = "Blue"
            elif self.ui.Theme_Yellow.isChecked():
                new_theme_value = "Yellow"
            elif self.ui.Theme_Customize.isChecked():
                
                current_theme_path = self.config_json.get("theme_color", "")
                if not os.path.exists(os.path.join(current_theme_path, "Color.json")):
                     path = str(QFileDialog.getExistingDirectory(self, "Select Custom Theme Folder", ""))
                     if path and os.path.exists(os.path.join(path, "Color.json")):
                         new_theme_value = path
                     else:
                         
                         self.ui.Theme_White.setChecked(True)
                         new_theme_value = "White"
                         self.info_event("Invalid custom theme folder selected. Reverted to White theme.")
                else:
                    
                    new_theme_value = current_theme_path

            
            if self.config_json.get("theme_color") != new_theme_value:
                 self.config_json["theme_color"] = new_theme_value
                 self.init_config_write(self.config_json)
                 self.init_change_color() 

        except Exception as e:
            print(f"Error changing theme: {e}")


    def init_change_color(self): 
        try:
            theme_name_or_path = self.config_json.get("theme_color", "White")
            self.theme = None 

            if theme_name_or_path in self.config_theme:
                
                self.theme = self.config_theme[theme_name_or_path]
                self.ui.State_icon.setPixmap(QPixmap(self.theme["icon"]))
            else:
                
                custom_theme_path = theme_name_or_path
                color_json_path = os.path.join(custom_theme_path, "Color.json")
                icon_path_relative = "" 

                if os.path.exists(color_json_path):
                    try:
                        with open(color_json_path, "r") as f:
                            self.theme = json.load(f)
                        
                        required_keys = ["icon", "button_on", "button_off", "widget_style", "window_style", "navigation_style"]
                        if not all(key in self.theme for key in required_keys):
                             raise ValueError("Custom theme JSON missing required keys.")

                        icon_path_relative = self.theme.get("icon", "")
                        icon_full_path = os.path.join(custom_theme_path, icon_path_relative)

                        if os.path.exists(icon_full_path):
                            self.ui.State_icon.setPixmap(QPixmap(icon_full_path))
                        else:
                            
                            print(f"Warning: Custom theme icon not found at {icon_full_path}. Using default.")
                            self.ui.State_icon.setPixmap(QPixmap(self.config_theme["White"]["icon"]))

                    except (json.JSONDecodeError, ValueError, Exception) as load_err:
                        print(f"Error loading custom theme from {custom_theme_path}: {load_err}")
                        self.theme = None 
                else:
                     print(f"Custom theme path or Color.json not found: {theme_name_or_path}")
                     self.theme = None 

            
            if self.theme is None:
                print("Falling back to White theme.")
                self.theme = self.config_theme["White"]
                self.config_json["theme_color"] = "White" 
                self.ui.Theme_White.setChecked(True) 
                self.init_config_write(self.config_json) 
                self.ui.State_icon.setPixmap(QPixmap(self.theme["icon"]))

            
            self.ui.Window_widget.setStyleSheet(self.theme["window_style"])
            self.ui.Navigation_Bar.setStyleSheet(self.theme["navigation_style"])
            
            self.ui.State_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Virus_Scan_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Tools_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Process_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Protection_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Setting_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.About_widget.setStyleSheet(self.theme["widget_style"])
            
            self.ui.widget_2.setStyleSheet(self.theme["widget_style"])

            
            
            self.ui.Virus_Scan_choose_Button.setStyleSheet(self.theme["button_on"]) 
            self.ui.Add_White_list_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Add_White_list_Button_3.setStyleSheet(self.theme["button_off"])
            self.ui.System_Process_Manage_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Clean_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Reset_Options_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button_2.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Network_Button.setStyleSheet(self.theme["button_off"])

            
            self._apply_toggle_button_style(self.ui.Protection_switch_Button)
            self._apply_toggle_button_style(self.ui.Protection_switch_Button_2)
            self._apply_toggle_button_style(self.ui.Protection_switch_Button_3)
            self._apply_toggle_button_style(self.ui.Protection_switch_Button_4)
            self._apply_toggle_button_style(self.ui.Protection_switch_Button_5)
            self._apply_toggle_button_style(self.ui.Protection_switch_Button_8)
            self._apply_toggle_button_style(self.ui.high_sensitivity_switch_Button)
            self._apply_toggle_button_style(self.ui.extension_kit_switch_Button)
            self._apply_toggle_button_style(self.ui.cloud_services_switch_Button)

        except Exception as e:
            print(f"Critical error applying theme colors: {e}")
            
            try:
                self.theme = self.config_theme["White"]
                self.config_json["theme_color"] = "White"
                self.init_config_write(self.config_json)
                
                self.init_change_color()
            except:
                 print("Failed to recover theme. UI might look incorrect.")


    def _apply_toggle_button_style(self, button):
        """Helper to apply on/off style based on button text."""
        if button.text() == "Enabled":
            button.setStyleSheet(self.theme["button_on"])
        else: 
            button.setStyleSheet(self.theme["button_off"])


    def init_config_done(self): 
        try:
            
            show_window = True
            if len(sys.argv) > 1:
                param = sys.argv[1].replace("/", "-")
                if "-h" in param or "-hidden" in param: 
                    show_window = False
                

            if show_window:
                self.init_config_show() 

            self.first_startup = 0 
        except Exception as e:
            print(f"Error in init_config_done: {e}")

    def init_config_func(self): 
        try:
             
            self._update_button_texts_from_config()
            
            self.init_change_color()

            
            if self.config_json.get("proc_protect", 0) == 1:
                Thread(target=self.protect_proc_thread, daemon=True).start()
            if self.config_json.get("file_protect", 0) == 1:
                Thread(target=self.protect_file_thread, daemon=True).start()
            if self.config_json.get("sys_protect", 0) == 1:
                Thread(target=self.protect_boot_thread, daemon=True).start()
                Thread(target=self.protect_reg_thread, daemon=True).start()
            if self.config_json.get("net_protect", 0) == 1:
                Thread(target=self.protect_net_thread, daemon=True).start()

            
            self.protect_drv_init(stop_only=False, initial_check=True)

            
            self.block_window_init() 
            self.gc_collect_init()   

        except Exception as e:
            print(f"Error initializing core functions: {e}")


    def protect_proc_init(self): 
        try:
            
            if self.ui.Protection_switch_Button.text() == "Enabled":
                
                self.config_json["proc_protect"] = 0
                self.ui.Protection_switch_Button.setText("Disabled")
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_off"])
                
            else:
                
                self.config_json["proc_protect"] = 1
                Thread(target=self.protect_proc_thread, daemon=True).start()
                self.ui.Protection_switch_Button.setText("Enabled")
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_on"])

            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_file_init(self): 
        try:
            if self.ui.Protection_switch_Button_2.text() == "Enabled":
                
                self.config_json["file_protect"] = 0
                self.ui.Protection_switch_Button_2.setText("Disabled")
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_off"])
            else:
                
                self.config_json["file_protect"] = 1
                Thread(target=self.protect_file_thread, daemon=True).start()
                self.ui.Protection_switch_Button_2.setText("Enabled")
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_sys_init(self): 
        try:
            if self.ui.Protection_switch_Button_3.text() == "Enabled":
                
                self.config_json["sys_protect"] = 0
                self.ui.Protection_switch_Button_3.setText("Disabled")
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_off"])
            else:
                
                self.config_json["sys_protect"] = 1
                
                if self.mbr_value:
                    Thread(target=self.protect_boot_thread, daemon=True).start()
                else:
                    print("Skipping boot protection thread: MBR not available.")
                Thread(target=self.protect_reg_thread, daemon=True).start()
                self.ui.Protection_switch_Button_3.setText("Enabled")
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)


    def protect_drv_init(self, stop_only=False, initial_check=False): 
        """
        Manages the PYAS_Driver service.
        :param stop_only: If True, only attempts to stop the driver (used during reset/cleanup).
        :param initial_check: If True, checks status without user interaction, updates button.
        """
        try:
            file_path = self.path_driver.replace("\\", "/")
            driver_bat_path = os.path.join(file_path, "Install_Driver.bat")
            uninstaller_bat_path = os.path.join(file_path, "Uninstall_Driver.bat")
            service_name = "PYAS_Driver"

            if not os.path.exists(driver_bat_path) or not os.path.exists(uninstaller_bat_path):
                 
                 self.ui.Protection_switch_Button_4.setText("Unavailable") 
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                 self.ui.Protection_switch_Button_4.setEnabled(False) 
                 return

            
            try:
                query_result = Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True)
                stdout, stderr = query_result.communicate()
                is_running = "RUNNING" in stdout
                is_stopped = "STOPPED" in stdout
                service_exists = "1060" not in stderr 

                
                if initial_check:
                    if is_running:
                         self.ui.Protection_switch_Button_4.setText("Enabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                    else:
                         self.ui.Protection_switch_Button_4.setText("Disabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                    return 

                
                if self.ui.Protection_switch_Button_4.text() == "Enabled" or stop_only:
                     if is_running:
                         
                         stop_cmd = f'sc stop {service_name}'
                         stop_result = Popen(stop_cmd, shell=True, stdout=PIPE, stderr=PIPE).wait()

                         if stop_result == 0 or "STOP_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                             
                             if not self.first_startup and not stop_only and os.path.exists(uninstaller_bat_path):
                                 if self.question_event("Driver protection stopped. Do you want to uninstall the driver? (Requires restart)"):
                                     Popen(f'"{uninstaller_bat_path}"', shell=True, stdout=PIPE, stderr=PIPE)
                                     
                                     self.info_event("Please restart your computer to complete driver uninstallation.")
                                     
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                                 else:
                                     
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                             else:
                                 
                                 self.ui.Protection_switch_Button_4.setText("Disabled")
                                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                         else:
                             self.info_event(f"Failed to stop driver service (Error code: {stop_result}). Manual check may be needed.")
                             
                     elif is_stopped and not stop_only:
                         
                         self.ui.Protection_switch_Button_4.setText("Disabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                     elif not service_exists and not stop_only:
                          
                          self.ui.Protection_switch_Button_4.setText("Disabled")
                          self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                     

                
                elif self.ui.Protection_switch_Button_4.text() == "Disabled" and not stop_only:
                     if not service_exists:
                         
                         if self.question_event("This option may conflict with other software and requires installing a driver. Are you sure you want to enable it? (Requires restart)"):
                             
                             Popen(f'sc delete {service_name}', shell=True, stdout=PIPE, stderr=PIPE).wait()
                             install_result = Popen(f'"{driver_bat_path}"', shell=True, stdout=PIPE, stderr=PIPE).wait()
                             if install_result == 0:
                                 
                                 start_result = Popen(f'sc start {service_name}', shell=True, stdout=PIPE, stderr=PIPE).wait()
                                 if start_result == 0 or "START_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                                     self.info_event("Driver installed and started successfully. A restart is recommended.")
                                     self.ui.Protection_switch_Button_4.setText("Enabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                                 else:
                                     self.info_event(f"Driver installed, but failed to start (Error code: {start_result}). Please restart your computer.")
                                     
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                             else:
                                 self.info_event(f"Driver installation failed (Error code: {install_result}).")
                                 
                         
                     elif is_stopped:
                         
                         start_cmd = f'sc start {service_name}'
                         start_result = Popen(start_cmd, shell=True, stdout=PIPE, stderr=PIPE).wait()
                         if start_result == 0 or "START_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                              self.ui.Protection_switch_Button_4.setText("Enabled")
                              self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                         else:
                              self.info_event(f"Failed to start existing driver service (Error code: {start_result}). It might require reinstallation or a restart.")
                              
                     elif is_running:
                         
                         self.ui.Protection_switch_Button_4.setText("Enabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])

            except FileNotFoundError:
                 print("Error: 'sc' command not found. Driver management requires Windows.")
                 self.ui.Protection_switch_Button_4.setText("Unavailable")
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                 self.ui.Protection_switch_Button_4.setEnabled(False)
            except Exception as e:
                 print(f"Error managing driver protection: {e}")
                 
                 self.ui.Protection_switch_Button_4.setText("Error")
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])

        except Exception as e:
            print(f"General error in protect_drv_init: {e}")


    def protect_net_init(self): 
        try:
            if self.ui.Protection_switch_Button_5.text() == "Enabled":
                
                self.config_json["net_protect"] = 0
                self.ui.Protection_switch_Button_5.setText("Disabled")
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_off"])
            else:
                
                self.config_json["net_protect"] = 1
                Thread(target=self.protect_net_thread, daemon=True).start()
                self.ui.Protection_switch_Button_5.setText("Enabled")
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_cus_init(self): 
        self.info_event("This feature is not currently supported.")
        
        self.config_json["cus_protect"] = 0
        self.ui.Protection_switch_Button_8.setText("Disabled")
        self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_off"])
        
        self.init_config_write(self.config_json) 

    def change_sensitive(self): 
        if self.ui.high_sensitivity_switch_Button.text() == "Enabled":
            
            self.config_json["sensitivity"] = 0
            self.ui.high_sensitivity_switch_Button.setText("Disabled")
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_off"])
        elif self.first_startup or self.question_event("This option may increase false positives. Are you sure you want to enable it?"):
            
            self.config_json["sensitivity"] = 1
            self.ui.high_sensitivity_switch_Button.setText("Enabled")
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_on"])
        
        self.init_config_write(self.config_json)

    def extension_kit(self): 
        if self.ui.extension_kit_switch_Button.text() == "Enabled":
             
            self.config_json["extend_mode"] = 0
            self.ui.extension_kit_switch_Button.setText("Disabled")
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_off"])
        else:
             
            self.config_json["extend_mode"] = 1
            self.ui.extension_kit_switch_Button.setText("Enabled")
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_on"])
        self.init_config_write(self.config_json)

    def cloud_services(self): 
        self.info_event("This feature is not currently supported.")
        
        self.config_json["service_url"] = "None" 
        self.ui.cloud_services_switch_Button.setText("Disabled")
        self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_off"])
        
        self.init_config_write(self.config_json) 


    def gc_collect_init(self): 
        try:
            self.gc_collect = 1
            Thread(target=self.gc_collect_thread, daemon=True).start()
        except Exception as e:
            print(e)

    def gc_collect_thread(self): 
        while self.gc_collect:
            try:
                
                
                time.sleep(5)
                collected = gc.collect()
                
            except Exception as e:
                print(f"Error in GC thread: {e}")
                
                time.sleep(30)


    def block_window_init(self): 
        try:
            
            if self.config_json.get("block_lists") and isinstance(self.config_json["block_lists"], list) and len(self.config_json["block_lists"]) > 0:
                 self.block_window = 1
                 Thread(target=self.block_software_window, daemon=True).start()
            else:
                 self.block_window = 0 
        except Exception as e:
            print(f"Error initializing window blocking: {e}")

    def add_white_list(self): 
        try:
            
            dialog = QFileDialog(self, "Add Item to Whitelist")
            dialog.setFileMode(QFileDialog.ExistingFiles) 
            if dialog.exec_():
                selected_items = dialog.selectedFiles()
                added_count = 0
                if selected_items:
                    items_to_add = [item.replace("\\", "/") for item in selected_items]
                    if self.question_event(f"Add the following {len(items_to_add)} item(s) to the whitelist?\n" + "\n".join(items_to_add)):
                        
                        if not isinstance(self.config_json.get("white_lists"), list):
                            self.config_json["white_lists"] = []

                        for item_path in items_to_add:
                             if item_path not in self.config_json["white_lists"]:
                                 self.config_json["white_lists"].append(item_path)
                                 added_count += 1

                        if added_count > 0:
                            self.info_event(f"Successfully added {added_count} item(s) to the whitelist.")
                            self.init_config_write(self.config_json)
                        else:
                            self.info_event("Selected item(s) were already in the whitelist.")
        except Exception as e:
            print(f"Error adding to whitelist: {e}")


    def remove_white_list(self): 
         try:
            
            
            dialog = QFileDialog(self, "Remove Item from Whitelist")
            dialog.setFileMode(QFileDialog.ExistingFiles)
            if dialog.exec_():
                selected_items = dialog.selectedFiles()
                removed_count = 0
                if selected_items:
                    items_to_remove = [item.replace("\\", "/") for item in selected_items]

                    
                    current_whitelist = self.config_json.get("white_lists", [])
                    found_items = [item for item in items_to_remove if item in current_whitelist]

                    if not found_items:
                         self.info_event("Selected item(s) not found in the whitelist.")
                         return

                    if self.question_event(f"Remove the following {len(found_items)} item(s) from the whitelist?\n" + "\n".join(found_items)):
                         if isinstance(current_whitelist, list):
                             for item_path in found_items:
                                 try:
                                     current_whitelist.remove(item_path)
                                     removed_count += 1
                                 except ValueError:
                                     pass 

                             if removed_count > 0:
                                 self.config_json["white_lists"] = current_whitelist 
                                 self.info_event(f"Successfully removed {removed_count} item(s) from the whitelist.")
                                 self.init_config_write(self.config_json)
                             
         except Exception as e:
             print(f"Error removing from whitelist: {e}")

    def add_software_window(self): 
        try:
            self.block_window = 0 
            if self.question_event("Please click on the window you want to block after closing this message."):
                
                time.sleep(0.5)
                
                while True:
                    QApplication.processEvents() 
                    hWnd = self.user32.GetForegroundWindow()
                    if not hWnd: 
                        time.sleep(0.1)
                        continue

                    window_info = self.get_window_info(hWnd)

                    
                    is_ignored = False
                    if not any(window_info.values()) : 
                         is_ignored = True
                    else:
                         for ignored in self.pass_windows:
                             
                             
                             
                             if window_info == ignored:
                                 is_ignored = True
                                 break
                             
                             
                             
                             

                    if not is_ignored:
                         title = list(window_info.keys())[0]
                         class_name = list(window_info.values())[0]
                         confirm_text = f"Block this window?\nTitle: '{title}'\nClass: '{class_name}'"
                         if self.question_event(confirm_text):
                             
                             if not isinstance(self.config_json.get("block_lists"), list):
                                 self.config_json["block_lists"] = []

                             if window_info not in self.config_json["block_lists"]:
                                 self.config_json["block_lists"].append(window_info)
                                 self.info_event(f"Added to block list: {window_info}")
                                 self.init_config_write(self.config_json)
                             else:
                                 self.info_event(f"Window already in block list: {window_info}")
                         
                         break 
                    else:
                         
                         
                         pass

                    time.sleep(0.1) 
            

            self.block_window_init() 
        except Exception as e:
            print(f"Error adding window to block: {e}")
            self.block_window_init() 

    def remove_software_window(self): 
        try:
            self.block_window = 0 
            if self.question_event("Please click on the window you want to remove from the block list after closing this message."):
                time.sleep(0.5)
                while True:
                    QApplication.processEvents()
                    hWnd = self.user32.GetForegroundWindow()
                    if not hWnd:
                         time.sleep(0.1)
                         continue

                    window_info = self.get_window_info(hWnd)

                    
                    current_block_list = self.config_json.get("block_lists", [])
                    is_in_list = window_info in current_block_list

                    
                    
                    is_ignored = False
                    if not any(window_info.values()): is_ignored = True
                    else:
                         for ignored in self.pass_windows:
                             if window_info == ignored:
                                 is_ignored = True
                                 break

                    if not is_ignored:
                        title = list(window_info.keys())[0]
                        class_name = list(window_info.values())[0]

                        if is_in_list:
                             confirm_text = f"Remove this window from the block list?\nTitle: '{title}'\nClass: '{class_name}'"
                             if self.question_event(confirm_text):
                                 if isinstance(current_block_list, list):
                                     try:
                                         current_block_list.remove(window_info)
                                         self.config_json["block_lists"] = current_block_list
                                         self.info_event(f"Removed from block list: {window_info}")
                                         self.init_config_write(self.config_json)
                                     except ValueError:
                                         self.info_event("Window was not found in the list (might have been removed already).")
                             
                             break 
                        else:
                             
                             info_text = f"This window is not currently in the block list.\nTitle: '{title}'\nClass: '{class_name}'"
                             self.info_event(info_text)
                             
                             break

                    time.sleep(0.1)
            

            self.block_window_init() 
        except Exception as e:
            print(f"Error removing window from block list: {e}")
            self.block_window_init() 


    def get_window_info(self, hWnd): 
        try:
            length = self.user32.GetWindowTextLengthW(hWnd)
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            self.user32.GetWindowTextW(hWnd, title_buffer, length + 1)
            window_title = title_buffer.value

            class_buffer = ctypes.create_unicode_buffer(256) 
            self.user32.GetClassNameW(hWnd, class_buffer, 256)
            class_name = class_buffer.value

            return {window_title: class_name}
        except Exception as e:
             print(f"Error getting window info for HWND {hWnd}: {e}")
             return {'': ''} 


    def enum_windows_callback(self, hWnd, lParam): 
        
        
        
        
        self.hwnd_list.append(hWnd)
        return True 

    def get_all_windows(self): 
        self.hwnd_list = [] 
        
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        
        enum_proc = WNDENUMPROC(self.enum_windows_callback)
        
        self.user32.EnumWindows(enum_proc, 0)
        return self.hwnd_list

    def block_software_window(self):  
        print("Window blocking thread started.")
        while self.block_window:
            try:
                time.sleep(0.2) 
                current_block_list = self.config_json.get("block_lists", [])
                if not current_block_list: 
                    
                    
                    time.sleep(2)
                    continue

                
                all_hwnds = self.get_all_windows()

                for hWnd in all_hwnds:
                    
                    if not self.user32.IsWindow(hWnd):
                        continue

                    window_info = self.get_window_info(hWnd)

                    
                    if window_info in current_block_list:
                        print(f"Blocking window: {window_info}")
                        
                        self.user32.PostMessageW(hWnd, 0x0010, 0, 0) 
                        
                        time.sleep(0.05)
                        
                        if self.user32.IsWindow(hWnd):
                             print(f"Force closing window: {window_info}")
                             
                             self.user32.PostMessageW(hWnd, 0x0112, 0xF060, 0) 
                             
                             
                             
                        
                        time.sleep(0.1)

            except Exception as e:
                print(f"Error in window blocking thread: {e}")
                
                time.sleep(5)
        print("Window blocking thread stopped.")


    def init_config_show(self): 
        def update_opacity():
            current_opacity = self.windowOpacity()
            if current_opacity < 1.0:
                 new_opacity = min(current_opacity + 0.02, 1.0) 
                 self.setWindowOpacity(new_opacity)
            else:
                 self.opacity_timer.stop() 

        
        self.setWindowOpacity(0.0)
        self.show()

        
        self.opacity_timer = QTimer(self)
        self.opacity_timer.timeout.connect(update_opacity)
        self.opacity_timer.start(10) 


    def init_config_hide(self): 
        def update_opacity():
            current_opacity = self.windowOpacity()
            if current_opacity > 0.0:
                 new_opacity = max(current_opacity - 0.02, 0.0) 
                 self.setWindowOpacity(new_opacity)
            else:
                 self.opacity_timer.stop() 
                 self.hide() 

        
        if self.isVisible():
            self.opacity_timer = QTimer(self)
            self.opacity_timer.timeout.connect(update_opacity)
            self.opacity_timer.start(10) 


    def showMinimized(self): 
        
        
        
        
        

        
        self.showMinimized()


    def nativeEvent(self, eventType, message):
        
        try:
             
             if message:
                 msg = ctypes.wintypes.MSG.from_address(int(message))
                 
                 
                 if msg.message == 0x0010: 
                     
                     
                     
                     pass 
                 elif msg.message == 0x0112 and (msg.wParam & 0xFFF0) == 0xF060: 
                     
                     
                     
                     pass 

        except Exception as e:
             print(f"Error in nativeEvent: {e}")

        
        return super(MainWindow_Controller, self).nativeEvent(eventType, message)


    def closeEvent(self, event): 
        
        if self.question_event("Are you sure you want to exit PYAS and stop all protections?"):
            print("Exiting application...")
            
            self.init_config_write(self.config_json) 
            self.clean_function() 
            print("Cleanup complete. Accepting close event.")
            event.accept() 
            QApplication.quit() 
        else:
            print("Close event ignored by user.")
            event.ignore() 


    def show_menu(self): 
        
        if self.ui.About_widget.isHidden():
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.Setting_widget.hide()
            self.ui.About_widget.show()
            self.Process_Timer.stop() 
            
            self.change_animation_3(self.ui.About_widget, 0.5) 
            self.change_animation_5(self.ui.About_widget, 80, 50, 761, 481) 


    def update_database(self): 
        try:
            if self.question_event("Are you sure you want to check for updates?"):
                self.info_event("Update check feature is not implemented yet.")
                
                
                
                
                
                
                pass
        except Exception as e:
            print(f"Error during update check: {e}")

    

    def change_animation(self, widget): 
        """Animates widget sliding in from the left."""
        target_x = 80 
        start_x = target_x - 60 
        y = widget.pos().y() 
        width, height = 761, 481 

        widget.setGeometry(QRect(start_x, y, width, height)) 

        self.anim = QPropertyAnimation(widget, b"geometry")
        self.anim.setDuration(300) 
        self.anim.setStartValue(QRect(start_x, y, width, height))

        
        self.anim.setEasingCurve(QEasingCurve.OutCubic)

        
        
        

        self.anim.setEndValue(QRect(target_x, y, width, height)) 
        self.anim.start(QAbstractAnimation.DeleteWhenStopped) 


    def change_animation_3(self, widget, duration_sec): 
        """Animates widget fading in."""
        self.opacity_effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(self.opacity_effect)
        

        self.anim_opacity = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim_opacity.setDuration(int(duration_sec * 1000)) 
        self.anim_opacity.setStartValue(0.0) 
        self.anim_opacity.setEndValue(1.0)   
        self.anim_opacity.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_opacity.start(QAbstractAnimation.DeleteWhenStopped)


    


    def change_animation_4(self, widget, duration_ms, start_height, end_height): 
        """Animates widget height change."""
        x = widget.pos().x()
        y = widget.pos().y() 
        width = widget.width() 

        self.anim_height = QPropertyAnimation(widget, b"geometry")
        self.anim_height.setDuration(duration_ms)
        self.anim_height.setStartValue(QRect(x, y, width, start_height))
        self.anim_height.setEndValue(QRect(x, y, width, end_height))
        self.anim_height.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_height.start(QAbstractAnimation.DeleteWhenStopped)


    def change_animation_5(self, widget, target_x, target_y, target_width, target_height): 
        """Animates widget dropping down from above."""
        start_y = target_y - 45 

        widget.setGeometry(QRect(target_x, start_y, target_width, target_height)) 

        self.anim_drop = QPropertyAnimation(widget, b"geometry")
        self.anim_drop.setDuration(350) 
        self.anim_drop.setStartValue(QRect(target_x, start_y, target_width, target_height))

        
        self.anim_drop.setEasingCurve(QEasingCurve.OutBounce) 
        

        self.anim_drop.setEndValue(QRect(target_x, target_y, target_width, target_height)) 
        self.anim_drop.start(QAbstractAnimation.DeleteWhenStopped)


    

    def _switch_main_widget(self, widget_to_show):
        """Helper function to hide all main widgets and show the specified one with animation."""
        widgets = [
            self.ui.State_widget,
            self.ui.Virus_Scan_widget,
            self.ui.Tools_widget,
            self.ui.Protection_widget,
            self.ui.Process_widget, 
            self.ui.Setting_widget,
            self.ui.About_widget
        ]

        for widget in widgets:
             if widget.isVisible() and widget != widget_to_show:
                 widget.hide() 

        if widget_to_show.isHidden():
             
             if widget_to_show != self.ui.Process_widget:
                 self.Process_Timer.stop()

             
             widget_to_show.show()
             self.change_animation_3(widget_to_show, 0.3) 
             self.change_animation(widget_to_show)     

             
             if widget_to_show == self.ui.Process_widget:
                  self.process_list() 
                  self.Process_Timer.start(1000) 


    def change_setting_widget(self):
        self._switch_main_widget(self.ui.Setting_widget)

    def change_state_widget(self):
        self._switch_main_widget(self.ui.State_widget)

    def change_scan_widget(self):
        self._switch_main_widget(self.ui.Virus_Scan_widget)

    def change_tools_widget(self):
        self._switch_main_widget(self.ui.Tools_widget)

    def change_protect_widget(self):
        self._switch_main_widget(self.ui.Protection_widget)

    def change_tools(self, widget): 
        
        
        
        
        if widget == self.ui.Process_widget:
            self._switch_main_widget(self.ui.Process_widget)
        


    

    def mousePressEvent(self, event): 
        
        title_bar_rect = QRect(10, 10, self.width() - 20, 40) 
        if event.button() == Qt.LeftButton and title_bar_rect.contains(event.pos()):
            self.m_flag = True 
            
            self.m_Position = event.globalPos() - self.pos()
            event.accept()
            
            
            


    def mouseMoveEvent(self, event): 
        if self.m_flag and event.buttons() == Qt.LeftButton: 
            
            new_pos = event.globalPos() - self.m_Position
            self.move(new_pos)
            event.accept()


    def mouseReleaseEvent(self, event): 
        if event.button() == Qt.LeftButton:
            self.m_flag = False 
            
            
            


    
    
    
    
    
    
    


    def paintEvent(self, event): 
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing) 
        painter.setBrush(Qt.transparent) 

        
        outer_rect = self.rect()
        
        inner_rect = QRect(10, 10, outer_rect.width() - 20, outer_rect.height() - 20)

        
        
        
        

        
        
        
        

        
        painter.setPen(QPen(Qt.gray, 1)) 
        painter.setBrush(Qt.transparent) 
        painter.drawRoundedRect(inner_rect, 5, 5) 

        super().paintEvent(event) 


    

    def info_event(self, text): 
        try:
            print(f"[Info] > {text}")
            
            if not self.first_startup:
                QMessageBox.information(self, "Information", str(text), QMessageBox.Ok)
        except Exception as e:
            print(f"Error showing info event: {e}")


    def question_event(self, text): 
        try:
            print(f"[Quest] > {text}")
            
            
            reply = QMessageBox.question(self, "Confirmation", str(text),
                                          QMessageBox.Yes | QMessageBox.No, QMessageBox.No) 
            return reply == QMessageBox.Yes
            
        except Exception as e:
            print(f"Error showing question event: {e}")
            return False 


    def send_notify(self, text, notify_bar=True): 
        try:
            now_time = time.strftime('%Y-%m-%d %H:%M:%S')
            log_message = f"[{now_time}] {text}"
            print(f"[Notify] > {log_message}")

            
            QMetaObject.invokeMethod(self.ui.State_output, "append",
                                     Qt.QueuedConnection, Q_ARG(str, log_message))

            
            if notify_bar and not self.first_startup and self.tray_icon.isVisible():
                self.tray_icon.showMessage("Foxy Security Notification", text,
                                           QSystemTrayIcon.Information, 5000) 
        except Exception as e:
            print(f"Error sending notification: {e}")


    

    def process_list(self): 
        try:
            current_pids = self.get_process_list()
            if current_pids is None: return 

            
            
            if current_pids != self.exist_process: 
                Process_list_app_data = []
                for pid in sorted(list(current_pids)): 
                    QApplication.processEvents() 
                    h_process = self.kernel32.OpenProcess(0x1000 | 0x0400, False, pid) 
                    if h_process:
                        file = self.get_process_file(h_process) 
                        self.kernel32.CloseHandle(h_process)
                        if file: 
                            
                            Process_list_app_data.append((pid, f"[{pid}] > {file.replace('\\', '/')}"))
                        
                    

                
                self.Process_list_all_pid = [p[0] for p in Process_list_app_data]

                
                if len(self.Process_list_all_pid) != self.Process_quantity:
                    self.Process_quantity = len(self.Process_list_all_pid)
                    self.ui.Process_Total_View.setText(str(self.Process_quantity))

                process_display_list = [p[1] for p in Process_list_app_data]
                self.Process_sim.setStringList(process_display_list)
                self.ui.Process_list.setModel(self.Process_sim)

                
                self.exist_process = current_pids

        except Exception as e:
            print(f"Error updating process list: {e}")


    def process_list_menu(self, pos): 
        try:
            selected_indexes = self.ui.Process_list.selectedIndexes()
            if not selected_indexes: return 

            
            selected_row = selected_indexes[0].row()
            if selected_row < len(self.Process_list_all_pid):
                selected_pid = self.Process_list_all_pid[selected_row]
                selected_text = self.Process_sim.stringList()[selected_row] 

                
                hProcessCheck = self.kernel32.OpenProcess(0x1000, False, selected_pid) 
                file_path_check = ""
                if hProcessCheck:
                     file_path_check = self.get_process_file(hProcessCheck).replace('\\', '/')
                     self.kernel32.CloseHandle(hProcessCheck)

                
                self.Process_popMenu = QMenu(self)
                kill_Process_Action = QAction(f"End Process ({selected_pid})", self) 
                copy_Path_Action = QAction("Copy Path", self)
                

                self.Process_popMenu.addAction(kill_Process_Action)
                if file_path_check: 
                     self.Process_popMenu.addAction(copy_Path_Action)

                
                action = self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos))

                if action == kill_Process_Action:
                    
                    confirm_msg = f"Are you sure you want to terminate process:\n{selected_text}?"
                    if self.question_event(confirm_msg):
                        try:
                            
                            hProcessKill = self.kernel32.OpenProcess(0x0001, False, selected_pid) 
                            if hProcessKill:
                                if file_path_check == self.path_pyas:
                                     self.info_event("Cannot terminate the application itself this way. Use the close button.")
                                     self.kernel32.CloseHandle(hProcessKill)
                                     
                                else:
                                     
                                     success = self.kernel32.TerminateProcess(hProcessKill, 1) 
                                     self.kernel32.CloseHandle(hProcessKill)
                                     if success:
                                         self.info_event(f"Process {selected_pid} terminated.")
                                         
                                         self.process_list()
                                     else:
                                         self.info_event(f"Failed to terminate process {selected_pid}. (Error: {ctypes.get_last_error()})")
                            else:
                                self.info_event(f"Could not open process {selected_pid} to terminate (Permissions?).")
                        except Exception as kill_e:
                            self.info_event(f"Error terminating process {selected_pid}: {kill_e}")

                elif action == copy_Path_Action and file_path_check:
                     pyperclip.copy(file_path_check)
                     self.info_event(f"Path copied to clipboard: {file_path_check}")

        except IndexError:
             print("Index error in process list menu, list might be updating.")
        except Exception as e:
             print(f"Error in process list menu: {e}")


    

    def init_scan(self): 
        try:
            self.ui.Virus_Scan_text.setText("Initializing...")
            QApplication.processEvents() 

            
            try:
                
                locked_files = list(self.virus_lock.keys())
                for file in locked_files:
                    self.lock_file(file, False) 
            except Exception as unlock_err:
                print(f"Warning: Error unlocking previous files: {unlock_err}")
                self.virus_lock = {} 

            
            self.scan_file = True 
            self.total_scan = 0
            self.scan_time = time.time()
            self.virus_lock = {} 
            self.virus_list_ui = [] 

            
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.Virus_Scan_choose_widget.hide() 
            self.ui.Virus_Scan_choose_Button.hide()
            self.ui.Virus_Scan_Break_Button.show()
            self.ui.Virus_Scan_output.clear() 

            
            self.ui.Virus_Scan_title.setText("Scanning")

        except Exception as e:
            print(f"Error initializing scan: {e}")


    def Virus_Scan_output_menu(self, point): 
        selected_items = self.ui.Virus_Scan_output.selectedItems()
        if not selected_items: return

        item = selected_items[0] 
        item_text = item.text()

        
        file_path = ""
        if "]" in item_text:
             try:
                 file_path = item_text.split("] ", 1)[1]
             except IndexError:
                 pass 

        menu = QMenu(self)
        copyPathAction = menu.addAction("Copy Path")
        openLocationAction = menu.addAction("Open File Location")
        

        
        copyPathAction.setEnabled(bool(file_path))
        openLocationAction.setEnabled(bool(file_path) and os.path.exists(os.path.dirname(file_path)))

        action = menu.exec_(self.ui.Virus_Scan_output.mapToGlobal(point))

        if action == copyPathAction and file_path:
            pyperclip.copy(file_path.replace("/", "\\")) 
            self.info_event("Path copied to clipboard.")
        elif action == openLocationAction and file_path:
            try:
                 dir_path = os.path.dirname(file_path).replace("/", "\\")
                 
                 subprocess.run(['explorer', '/select,', dir_path + "\\" + os.path.basename(file_path)], check=True)
            except Exception as open_err:
                 self.info_event(f"Could not open file location: {open_err}")


    def lock_file(self, file_path, lock): 
        """Locks or unlocks a file using msvcrt locking."""
        try:
            if lock:
                
                if file_path not in self.virus_lock:
                    
                    handle = os.open(file_path, os.O_RDWR | os.O_BINARY)
                    file_size = os.path.getsize(file_path)
                    
                    msvcrt.locking(handle, msvcrt.LK_NBLCK, file_size if file_size > 0 else 1) 
                    self.virus_lock[file_path] = handle 
                    print(f"Locked: {file_path}")
            else:
                
                if file_path in self.virus_lock:
                    handle = self.virus_lock[file_path]
                    file_size = os.path.getsize(file_path) 
                    
                    msvcrt.locking(handle, msvcrt.LK_UNLCK, file_size if file_size > 0 else 1)
                    os.close(handle) 
                    del self.virus_lock[file_path] 
                    print(f"Unlocked: {file_path}")

        except OSError as e:
             
             print(f"OS Error locking/unlocking {file_path}: {e}")
             
             if lock and file_path in self.virus_lock:
                  del self.virus_lock[file_path]
             
             if not lock and file_path in self.virus_lock:
                  
                  try: os.close(self.virus_lock[file_path])
                  except: pass
                  del self.virus_lock[file_path]
        except Exception as e:
             print(f"General Error locking/unlocking file {file_path}: {e}")


    def virus_solve(self): 
        try:
            items_to_delete = []
            items_to_keep = [] 

            
            for i in range(self.ui.Virus_Scan_output.count()):
                item = self.ui.Virus_Scan_output.item(i)
                item_text = item.text()
                file_path = ""
                if "]" in item_text:
                     try: file_path = item_text.split("] ", 1)[1]
                     except IndexError: pass

                if file_path: 
                    if item.checkState() == Qt.Checked:
                        items_to_delete.append((item, file_path))
                    else:
                        items_to_keep.append((item, file_path))

            if not items_to_delete:
                self.info_event("No items selected for deletion.")
                return

            if not self.question_event(f"Are you sure you want to delete {len(items_to_delete)} selected item(s)? This action cannot be undone."):
                return 

            
            self.ui.Virus_Scan_Solve_Button.setEnabled(False) 
            self.ui.Virus_Scan_title.setText("Deleting Files...")
            QApplication.processEvents()

            deleted_count = 0
            failed_files = []

            for item, file_path in items_to_delete:
                 try:
                    
                    self.ui.Virus_Scan_text.setText(f"Deleting: {os.path.basename(file_path)}")
                    QApplication.processEvents()

                    
                    self.lock_file(file_path, False)

                    
                    if os.path.exists(file_path):
                         
                         os.remove(file_path)
                         deleted_count += 1
                         
                         
                         print(f"Deleted: {file_path}")
                    else:
                         print(f"File not found (already deleted?): {file_path}")
                         

                 except Exception as delete_err:
                     print(f"Failed to delete {file_path}: {delete_err}")
                     failed_files.append(os.path.basename(file_path))
                     

            
            
            self.ui.Virus_Scan_output.clear()
            self.virus_list_ui = [] 
            for item, file_path in items_to_keep:
                 
                 list_item = QListWidgetItem(item.text()) 
                 list_item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                 list_item.setCheckState(Qt.Unchecked) 
                 self.ui.Virus_Scan_output.addItem(list_item)
                 self.virus_list_ui.append(item.text()) 

            
            if failed_files or items_to_keep:
                 self.ui.Virus_Scan_title.setText("Deletion Complete (Failures Occurred)")
                 self.ui.Virus_Scan_text.setText(f"Deleted {deleted_count} items. Failed: {len(failed_files)}. Remaining: {len(items_to_keep)}.")
                 self.ui.Virus_Scan_Solve_Button.show() 
                 self.ui.Virus_Scan_Solve_Button.setEnabled(True)
                 self.info_event(f"Deletion finished. Failed to delete: {', '.join(failed_files)}")
            else:
                 self.ui.Virus_Scan_title.setText("Deletion Complete")
                 self.ui.Virus_Scan_text.setText(f"Successfully deleted {deleted_count} items.")
                 self.ui.Virus_Scan_Solve_Button.hide() 
                 self.ui.Virus_Scan_Break_Button.hide() 
                 self.ui.Virus_Scan_choose_Button.show() 

        except Exception as e:
            print(f"Error during virus solve process: {e}")
            self.ui.Virus_Scan_title.setText("Error During Deletion")
            self.ui.Virus_Scan_text.setText("An unexpected error occurred.")
            self.ui.Virus_Scan_Solve_Button.setEnabled(True) 


    def write_scan(self, state, file_path): 
        """Adds a formatted scan result to the Virus Scan output list."""
        try:
            if state and file_path:
                 display_text = f"[{state}] {file_path}"
                 
                 self.lock_file(file_path, True)
                 
                 self.virus_list_ui.append(display_text)
                 
                 item = QListWidgetItem(display_text)
                 item.setFlags(item.flags() | Qt.ItemIsUserCheckable) 
                 item.setCheckState(Qt.Checked) 
                 
                 QMetaObject.invokeMethod(self.ui.Virus_Scan_output, "addItem", Qt.QueuedConnection, Q_ARG(QListWidgetItem, item))
        except Exception as e:
             print(f"Error writing scan result for {file_path}: {e}")


    def answer_scan(self): 
        """Updates UI titles and buttons after a scan completes."""
        try:
            
            def update_ui():
                self.ui.Virus_Scan_title.setText("Virus Scan") 
                takes_time = int(time.time() - self.scan_time)
                if not self.virus_list_ui: 
                     result_text = f"Scan complete. No threats found."
                     summary_text = f"Scanned {self.total_scan} files in {takes_time} seconds."
                     self.ui.Virus_Scan_Solve_Button.hide()
                     self.ui.Virus_Scan_Break_Button.hide()
                     self.ui.Virus_Scan_choose_Button.show()
                else: 
                     found_count = len(self.virus_list_ui)
                     result_text = f"Scan complete. Found {found_count} threat(s)."
                     summary_text = f"Scanned {self.total_scan} files in {takes_time} seconds."
                     self.ui.Virus_Scan_Solve_Button.show()
                     self.ui.Virus_Scan_Break_Button.hide()
                     self.ui.Virus_Scan_choose_Button.show()

                final_text = f"{result_text} {summary_text}"
                self.ui.Virus_Scan_text.setText(final_text)
                self.send_notify(final_text, notify_bar=True) 

            
            if QThread.currentThread() != self.thread():
                 QTimer.singleShot(0, update_ui)
            else:
                 update_ui()

        except Exception as e:
            print(f"Error summarizing scan results: {e}")
            
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText", Qt.QueuedConnection, Q_ARG(str, "Virus Scan"))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, "Scan finished with errors."))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_Break_Button, "hide")
            QMetaObject.invokeMethod(self.ui.Virus_Scan_choose_Button, "show")


    def virus_scan_break(self): 
        print("Scan stop requested.")
        self.scan_file = False 
        
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()
        self.ui.Virus_Scan_title.setText("Scan Stopped")
        self.ui.Virus_Scan_text.setText("Scan stopped by user.")
        
        
        
        if self.virus_list_ui:
             self.ui.Virus_Scan_Solve_Button.show()


    def virus_scan_menu(self): 
        widget = self.ui.Virus_Scan_choose_widget
        if widget.isHidden():
            widget.show()
            
            self.change_animation_4(widget, 150, 0, 101) 
        else:
            
            self.change_animation_4(widget, 150, widget.height(), 0)
            
            QTimer.singleShot(160, widget.hide) 


    def _run_scan_thread(self, target_func, *args):
        """Helper to run a scan function in a thread and handle completion."""
        try:
            self.init_scan() 

            
            self.scan_thread = Thread(target=target_func, args=args, daemon=True)
            self.scan_thread.start()

            
            self.scan_check_timer = QTimer(self)
            def check_scan_finish():
                if not self.scan_thread.is_alive():
                    self.scan_check_timer.stop()
                    
                    QTimer.singleShot(0, self.answer_scan) 
                else:
                    
                    QApplication.processEvents()

            self.scan_check_timer.timeout.connect(check_scan_finish)
            self.scan_check_timer.start(100) 

        except Exception as e:
            print(f"Error starting scan thread for {target_func.__name__}: {e}")
            self.virus_scan_break() 


    def file_scan(self): 
        try:
            options = QFileDialog.Options()
            
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*);;Executable Files (*.exe *.dll *.sys)", options=options)

            if file_path:
                file_path = file_path.replace("\\", "/")
                if self.check_whitelist(file_path):
                    self.info_event(f"File is in whitelist, skipping scan: {file_path}")
                    return

                
                def scan_single_file(f_path):
                    scan_result = self.start_scan(f_path)
                    self.write_scan(scan_result, f_path) 
                    self.total_scan += 1

                
                self._run_scan_thread(scan_single_file, file_path)

        except Exception as e:
            print(f"Error during file scan setup: {e}")
            self.virus_scan_break()


    def path_scan(self): 
        try:
            options = QFileDialog.Options()
            options |= QFileDialog.ShowDirsOnly
            
            dir_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan", "", options=options)

            if dir_path:
                dir_path = dir_path.replace("\\", "/")
                if self.check_whitelist(dir_path):
                     self.info_event(f"Folder is within a whitelisted path, skipping scan: {dir_path}")
                     return

                
                self._run_scan_thread(self.traverse_path, dir_path)

        except Exception as e:
            print(f"Error during path scan setup: {e}")
            self.virus_scan_break()


    def disk_scan(self): 
        try:
            drives = [f"{chr(l)}:/" for l in range(65, 91) if os.path.exists(f"{chr(l)}:/")]
            if not drives:
                 self.info_event("No drives found to scan.")
                 return

            if not self.question_event(f"This will scan all files on drive(s): {', '.join(drives)}. This may take a long time. Continue?"):
                return

            
            def scan_all_drives(drive_list):
                 for drive in drive_list:
                     if not self.scan_file: break 
                     print(f"Scanning drive: {drive}")
                     
                     QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, f"Scanning drive {drive}..."))
                     self.traverse_path(drive) 

            
            self._run_scan_thread(scan_all_drives, drives)

        except Exception as e:
            print(f"Error during disk scan setup: {e}")
            self.virus_scan_break()


    def traverse_path(self, root_path): 
        """Traverses a path, scanning files and subdirectories."""
        try:
            
            for entry in os.scandir(root_path):
                if not self.scan_file: 
                    print("Traversal stopped.")
                    break
                try:
                    file_path = entry.path.replace("\\", "/")

                    
                    if self.check_whitelist(file_path):
                        
                        continue

                    
                    
                    if self.total_scan % 50 == 0: 
                         QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, file_path))

                    if entry.is_dir(follow_symlinks=False):
                         self.traverse_path(file_path) 
                    elif entry.is_file(follow_symlinks=False):
                         
                         scan_result = self.start_scan(file_path)
                         self.write_scan(scan_result, file_path) 
                         self.total_scan += 1

                except PermissionError:
                    
                    pass 
                except FileNotFoundError:
                    
                    pass 
                except Exception as traverse_err:
                    print(f"Error processing {entry.path}: {traverse_err}")
        except PermissionError:
             print(f"Permission denied accessing root path: {root_path}")
        except FileNotFoundError:
             print(f"Path not found: {root_path}")
        except Exception as e:
            print(f"Error traversing path {root_path}: {e}")


    def start_scan(self, file_path): 
        """Scans a file using configured engines and returns the result label/level."""
        primary_result = None
        secondary_result = None

        
        try:
            label, level = self.model.dl_scan(file_path)
            if label: 
                 
                 is_sensitive = self.config_json.get("sensitivity", 0) == 1
                 
                 medium_threshold = getattr(self.model, 'values', 0.75) 

                 
                 if is_sensitive or (level >= medium_threshold):
                     primary_result = f"{label}.DL{int(level*100)}" 

        except Exception as e:
            
            print(f"Error during DL scan for {file_path}: {e}")

        
        
        
        if self.config_json.get("extend_mode", 0) == 1:
            try:
                
                label, match_info = self.rules.yr_scan(file_path)
                if label and match_info:
                    
                    secondary_result = f"{label}.YR_{match_info}" 

            except Exception as e:
                 print(f"Error during YARA scan for {file_path}: {e}")

        
        
        
        if primary_result:
             return primary_result
        elif secondary_result:
             return secondary_result
        else:
             return False 


    

    def repair_system(self): 
        try:
            if self.question_event("This will attempt to repair common system file associations, restrictions, and registry settings. Are you sure?"):
                self.info_event("Starting system repair...")
                QApplication.processEvents() 

                success_count = 0
                fail_count = 0

                
                repair_steps = {
                    "Wallpaper": self.repair_system_wallpaper,
                    "Restrictions": self.repair_system_restrict,
                    "File Types": self.repair_system_file_type,
                    "Icons": self.repair_system_file_icon,
                    "Image Hijacks": self.repair_system_image
                }

                for name, func in repair_steps.items():
                    try:
                        print(f"Repairing: {name}...")
                        func()
                        success_count += 1
                    except Exception as step_err:
                         print(f"Failed to repair {name}: {step_err}")
                         fail_count += 1
                    QApplication.processEvents() 

                
                if fail_count == 0:
                    self.info_event(f"System repair completed successfully ({success_count} steps). A restart may be required for all changes.")
                else:
                    self.info_event(f"System repair finished. Success: {success_count}, Failures: {fail_count}. Check console for details. A restart may be required.")

        except Exception as e:
            print(f"Error during system repair process: {e}")
            self.info_event("An error occurred during system repair.")


    
    
    HKEY_CLASSES_ROOT = 0x80000000
    HKEY_CURRENT_USER = 0x80000001
    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_USERS = 0x80000003

    
    KEY_READ = 0x20019
    KEY_WRITE = 0x20006
    KEY_ALL_ACCESS = 0xF003F

    def open_registry_key(self, hkey_root, subkey_path, access=KEY_READ):
        """Opens a registry key and returns the handle."""
        key_handle = ctypes.wintypes.HKEY()
        try:
            result = self.advapi32.RegOpenKeyExW(
                hkey_root,        
                subkey_path,      
                0,                
                access,           
                ctypes.byref(key_handle) 
            )
            if result == 0: 
                return key_handle
            else:
                
                return None
        except Exception as e:
             print(f"Exception opening registry key {subkey_path}: {e}")
             return None

    def close_registry_key(self, key_handle):
        """Closes an open registry key handle."""
        if key_handle:
            try:
                self.advapi32.RegCloseKey(key_handle)
            except Exception as e:
                 print(f"Exception closing registry key handle: {e}")


    def delete_registry_key(self, hkey_root_or_handle, subkey_name):
        """Deletes a registry subkey. Requires parent handle or root + parent path."""
        
        
        
        try:
            
            result = self.advapi32.RegDeleteKeyW(hkey_root_or_handle, subkey_name)
            if result == 0:
                print(f"Deleted registry key: {subkey_name}")
                
                if self.track_proc and self.config_json.get("sys_protect",0):
                    self.kill_process("Registry Tampering (Key Deletion)", *self.track_proc)
                return True
            else:
                
                return False
        except Exception as e:
            print(f"Exception deleting registry key {subkey_name}: {e}")
            return False


    def delete_registry_value(self, hkey_handle, value_name):
        """Deletes a registry value from an open key handle."""
        try:
            result = self.advapi32.RegDeleteValueW(hkey_handle, value_name)
            if result == 0:
                
                
                if self.track_proc and self.config_json.get("sys_protect",0):
                    self.kill_process("Registry Tampering (Value Deletion)", *self.track_proc)
                return True
            elif result == 2: 
                 return True
            else:
                
                return False
        except Exception as e:
            print(f"Exception deleting registry value {value_name}: {e}")
            return False


    def create_registry_key(self, hkey_root, subkey_path):
        """Creates a registry key if it doesn't exist."""
        key_handle = ctypes.wintypes.HKEY()
        disposition = ctypes.wintypes.DWORD() 
        try:
            result = self.advapi32.RegCreateKeyExW(
                hkey_root,        
                subkey_path,      
                0,                
                None,             
                0,                
                self.KEY_WRITE,   
                None,             
                ctypes.byref(key_handle), 
                ctypes.byref(disposition) 
            )
            if result == 0:
                 self.close_registry_key(key_handle) 
                 
                 return True
            else:
                 print(f"Failed to create/open registry key {subkey_path}. Error code: {result}")
                 return False
        except Exception as e:
             print(f"Exception creating registry key {subkey_path}: {e}")
             return False


    def set_registry_value(self, hkey_root, subkey_path, value_name, value_data, value_type=1):
        """Sets a registry value (REG_SZ = 1 by default)."""
        key_handle = self.open_registry_key(hkey_root, subkey_path, self.KEY_WRITE)
        if not key_handle:
            print(f"Cannot open key {subkey_path} to set value '{value_name}'.")
            
            if self.create_registry_key(hkey_root, subkey_path):
                 key_handle = self.open_registry_key(hkey_root, subkey_path, self.KEY_WRITE)
                 if not key_handle:
                      print(f"Still cannot open key {subkey_path} after attempting creation.")
                      return False
            else:
                 return False 

        try:
            if value_type == 1: 
                value_buffer = ctypes.create_unicode_buffer(value_data)
                
                data_size = (len(value_data) + 1) * ctypes.sizeof(ctypes.wintypes.WCHAR)
            
            
            
            
            else:
                print(f"Unsupported registry value type: {value_type}")
                self.close_registry_key(key_handle)
                return False

            result = self.advapi32.RegSetValueExW(
                key_handle,       
                value_name,       
                0,                
                value_type,       
                ctypes.byref(value_buffer), 
                data_size         
            )
            if result == 0:
                
                
                return True
            else:
                print(f"Failed to set registry value '{value_name}' in {subkey_path}. Error code: {result}")
                return False
        except Exception as e:
            print(f"Exception setting registry value '{value_name}' in {subkey_path}: {e}")
            return False
        finally:
            self.close_registry_key(key_handle)


    

    def repair_system_restrict(self): 
        """Removes common UI/system restrictions from Policies keys."""
        
        restrictions = [
            "NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu",
            "NoSetFolders", "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop",
            "NoLogOff", "NoFolderOptions", "RestrictRun", "NoViewContexMenu", "HideClock",
            "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic", "DisableCMD",
            "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks",
            "DisableLockWorkstation", "Restrict_Run", "DisableTaskMgr", "DisableRegistryTools",
            "DisableChangePassword", "NoComponents", "NoAddingComponents", "NoStartMenuPinnedList",
            "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu",
            "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu",
            "NoViewContextMenu", "NoManageMyComputerVerb", "NoWindowsUpdate", "ClearRecentDocsOnExit",
            "NoStartMenuNetworkPlaces", "Wallpaper" 
        ]
        
        policy_keys = [
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"),
            (self.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\System"), 
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System"), 
            
            
            
        ]

        for hkey, subkey in policy_keys:
            key_handle = self.open_registry_key(hkey, subkey, self.KEY_WRITE)
            if key_handle:
                
                for value_name in restrictions:
                    
                    self.delete_registry_value(key_handle, value_name)
                self.close_registry_key(key_handle)
            


    def repair_system_image(self): 
        """Removes debugger entries from IFEO keys, except known safe ones."""
        ifeo_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        
        
        known_safe_exes = ['procexp.exe', 'procexp64.exe', 'werfault.exe']

        key_handle = self.open_registry_key(self.HKEY_LOCAL_MACHINE, ifeo_path, self.KEY_ALL_ACCESS)
        if not key_handle:
            print(f"Could not open IFEO key: {ifeo_path}")
            return

        try:
            
            num_subkeys = ctypes.wintypes.DWORD()
            self.advapi32.RegQueryInfoKeyW(key_handle, None, None, None, ctypes.byref(num_subkeys),
                                            None, None, None, None, None, None, None)

            
            for i in range(num_subkeys.value):
                subkey_name_buffer = ctypes.create_unicode_buffer(260) 
                subkey_name_len = ctypes.wintypes.DWORD(260)
                result = self.advapi32.RegEnumKeyExW(key_handle, i, subkey_name_buffer,
                                                     ctypes.byref(subkey_name_len), None, None, None, None)

                if result == 0: 
                    exe_name = subkey_name_buffer.value
                    
                    if exe_name.lower() in known_safe_exes:
                         
                         continue

                    
                    exe_key_path = os.path.join(ifeo_path, exe_name).replace("\\","/") 
                    exe_key_handle = self.open_registry_key(self.HKEY_LOCAL_MACHINE, exe_key_path, self.KEY_READ | self.KEY_WRITE)

                    if exe_key_handle:
                        
                        debugger_value_buffer = ctypes.create_unicode_buffer(1024)
                        debugger_value_size = ctypes.wintypes.DWORD(1024 * ctypes.sizeof(ctypes.wintypes.WCHAR))
                        debugger_value_type = ctypes.wintypes.DWORD()

                        value_result = self.advapi32.RegQueryValueExW(
                            exe_key_handle, "Debugger", None, ctypes.byref(debugger_value_type),
                            ctypes.cast(debugger_value_buffer, ctypes.POINTER(ctypes.wintypes.BYTE)),
                            ctypes.byref(debugger_value_size)
                        )

                        if value_result == 0: 
                             print(f"Removing potential hijack for {exe_name} (Debugger: {debugger_value_buffer.value})")
                             
                             self.delete_registry_value(exe_key_handle, "Debugger")
                             
                             

                        self.close_registry_key(exe_key_handle)
                    else:
                         print(f"Warning: Could not open IFEO subkey {exe_name} to check for debugger.")

                
                
                else:
                    print(f"Error enumerating IFEO subkey at index {i}. Error code: {result}")

        except Exception as e:
            print(f"Exception processing IFEO entries: {e}")
        finally:
            self.close_registry_key(key_handle)


    def repair_system_file_icon(self): 
        """Resets the default icon for .exe files."""
        try:
            
            base_path = r'SOFTWARE\Classes'
            exe_key = r'exefile\DefaultIcon'
            default_icon_value = r'%1' 

            
            self.set_registry_value(self.HKEY_LOCAL_MACHINE, os.path.join(base_path, exe_key), "", default_icon_value)

            
            

            
            

        except Exception as e:
            print(f"Error repairing file icon: {e}")


    def repair_system_file_type(self): 
        """Repairs .exe file association and open command."""
        try:
            
            hkey = self.HKEY_LOCAL_MACHINE
            base_path = r'SOFTWARE\Classes'

            
            self.set_registry_value(hkey, os.path.join(base_path, '.exe'), "", 'exefile')

            
            self.set_registry_value(hkey, os.path.join(base_path, 'exefile'), "", 'Application')

            
            open_command_path = os.path.join(base_path, r'exefile\shell\open\command')
            open_command_value = r'"%1" %*' 
            self.set_registry_value(hkey, open_command_path, "", open_command_value)

            
            

        except Exception as e:
            print(f"Error repairing file type association: {e}")


    def repair_system_wallpaper(self): 
        """Resets the desktop wallpaper to the default Windows image."""
        try:
            
            default_wallpaper = r"C:\Windows\Web\Wallpaper\Windows\img0.jpg"

            if not os.path.exists(default_wallpaper):
                print("Default wallpaper image not found. Skipping wallpaper reset.")
                
                return

            
            wallpaper_key = r"Control Panel\Desktop"
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "Wallpaper", default_wallpaper)

            
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "WallpaperStyle", "0") 
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "TileWallpaper", "1")  

            
            SPI_SETDESKWALLPAPER = 0x0014
            SPIF_UPDATEINIFILE = 0x01 
            SPIF_SENDCHANGE = 0x02     

            result = self.user32.SystemParametersInfoW(
                SPI_SETDESKWALLPAPER,
                0,                     
                default_wallpaper,     
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE 
            )
            if not result:
                 print(f"SystemParametersInfo failed to set wallpaper. Error: {ctypes.get_last_error()}")

        except Exception as e:
            print(f"Error repairing wallpaper: {e}")


    def repair_network(self): 
        """Resets Winsock and prompts for restart."""
        try:
            if self.question_event("This will reset the network configuration (Winsock). You will likely need to restart your computer. Are you sure?"):
                self.info_event("Running 'netsh winsock reset'...")
                QApplication.processEvents() 

                
                process = Popen("netsh winsock reset", shell=True, stdout=PIPE, stderr=PIPE, text=True, creationflags=CREATE_NO_WINDOW)
                stdout, stderr = process.communicate()
                exit_code = process.wait()

                if exit_code == 0:
                    print("Winsock reset successful.")
                    if self.question_event("Network reset completed successfully. Restart required to apply changes. Restart now?"):
                        self.info_event("Restarting computer...")
                        Popen("shutdown -r -t 5 -c \"PYAS requested restart after network repair.\"", shell=True, stdout=PIPE, stderr=PIPE, creationflags=CREATE_NO_WINDOW)
                        
                        self.close() 
                    else:
                         self.info_event("Network reset complete. Please restart your computer manually.")
                else:
                    self.info_event(f"Network reset command failed (Exit Code: {exit_code}).\nError: {stderr}")

        except FileNotFoundError:
             self.info_event("Error: 'netsh' command not found. Cannot reset network.")
        except Exception as e:
            print(f"Error during network repair: {e}")
            self.info_event("An error occurred during network repair.")


    def clean_system(self): 
        """Cleans system temporary folders and optionally the Recycle Bin."""
        try:
            
            paths_to_clean = []
            
            paths_to_clean.append(os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "Temp"))
            
            paths_to_clean.append(os.environ.get("TEMP", ""))
            
            

            
            
            clean_recycle_bin = False
            try:
                import winshell
                if self.question_event("Do you also want to empty the Recycle Bin?"):
                    clean_recycle_bin = True
            except ImportError:
                 print("Optional: 'winshell' library not found. Skipping Recycle Bin cleaning.")
                 

            
            if self.question_event("This will delete files from temporary locations. Are you sure?"):
                self.info_event("Starting system cleaning...")
                QApplication.processEvents()

                self.total_deleted_size = 0
                self.total_deleted_count = 0
                self.total_failed_count = 0

                
                for path in paths_to_clean:
                    if path and os.path.isdir(path):
                        print(f"Cleaning path: {path}")
                        self.traverse_and_delete(path)
                    else:
                         print(f"Skipping invalid or non-existent path: {path}")

                
                if clean_recycle_bin:
                     try:
                         print("Emptying Recycle Bin...")
                         winshell.recycle_bin().empty(confirm=False, show_progress=False, sound=False)
                         print("Recycle Bin emptied.")
                     except Exception as rb_err:
                         print(f"Failed to empty Recycle Bin: {rb_err}")
                         self.total_failed_count += 1 

                
                size_mb = self.total_deleted_size / (1024 * 1024)
                result_msg = f"Cleaning finished. Deleted {self.total_deleted_count} files ({size_mb:.2f} MB)."
                if self.total_failed_count > 0:
                    result_msg += f" Failed to delete {self.total_failed_count} items."
                self.info_event(result_msg)

        except Exception as e:
            print(f"Error during system cleaning: {e}")
            self.info_event("An error occurred during system cleaning.")


    def traverse_and_delete(self, directory_path):
        """Recursively deletes files and folders within a directory."""
        for entry in os.scandir(directory_path):
            try:
                QApplication.processEvents() 

                if entry.is_file(follow_symlinks=False):
                    file_size = entry.stat().st_size
                    os.remove(entry.path)
                    self.total_deleted_size += file_size
                    self.total_deleted_count += 1
                    
                    

                elif entry.is_dir(follow_symlinks=False):
                     
                     self.traverse_and_delete(entry.path)
                     
                     os.rmdir(entry.path)
                     

            except PermissionError:
                
                self.total_failed_count += 1
            except OSError as os_err:
                
                
                
                self.total_failed_count += 1
            except Exception as del_err:
                print(f"Unexpected error deleting {entry.path}: {del_err}")
                self.total_failed_count += 1


    

    def protect_proc_thread(self): 
        """Monitors for new processes and scans them."""
        print("Process protection thread started.")
        while self.config_json.get("proc_protect", 0) == 1:
            try:
                time.sleep(0.1) 
                current_process_set = self.get_process_list()
                if current_process_set is None: continue 

                
                new_pids = current_process_set - self.exist_process

                if new_pids:
                     
                     for pid in new_pids:
                          if pid == 0 or pid == 4: continue 
                          self.handle_new_process(pid)

                
                self.exist_process = current_process_set

            except Exception as e:
                print(f"Error in process protection thread: {e}")
                time.sleep(1) 
        print("Process protection thread stopped.")


    def get_process_list(self): 
        """Returns a set of all current process IDs."""
        try:
            pid_set = set()
            
            
            buffer_size = 1024 * ctypes.sizeof(ctypes.wintypes.DWORD)
            process_ids = (ctypes.wintypes.DWORD * 1024)()
            bytes_returned = ctypes.wintypes.DWORD()

            
            if self.psapi.EnumProcesses(ctypes.byref(process_ids), buffer_size, ctypes.byref(bytes_returned)):
                
                if bytes_returned.value >= buffer_size:
                     
                     
                     new_size = bytes_returned.value
                     num_pids_estimated = new_size // ctypes.sizeof(ctypes.wintypes.DWORD)
                     process_ids = (ctypes.wintypes.DWORD * num_pids_estimated)()
                     buffer_size = new_size
                     if not self.psapi.EnumProcesses(ctypes.byref(process_ids), buffer_size, ctypes.byref(bytes_returned)):
                          print(f"Failed EnumProcesses even after resize. Error: {ctypes.get_last_error()}")
                          return None 
                     
                     num_pids = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)
                else:
                     num_pids = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)

                
                for i in range(num_pids):
                    pid_set.add(process_ids[i])

                return pid_set
            else:
                print(f"Failed EnumProcesses. Error: {ctypes.get_last_error()}")
                return None
        except Exception as e:
            print(f"Exception getting process list: {e}")
            return None


    def handle_new_process(self, pid): 
        """Opens, scans, and potentially terminates a new process."""
        h_process = None 
        try:
            
            
            access_flags = 0x1000 | 0x0400 | 0x0010 | 0x0002 | 0x0001 
            h_process = self.kernel32.OpenProcess(access_flags, False, pid)

            if not h_process:
                 
                 return

            
            file_path = self.get_process_file(h_process)
            if not file_path or not os.path.exists(file_path):
                
                self.kernel32.CloseHandle(h_process)
                return

            file_path = file_path.replace("\\", "/") 

            
            if self.check_whitelist(file_path):
                
                self.kernel32.CloseHandle(h_process)
                return

            
            
            self.lock_process(h_process, True) 

            
            scan_result = self.start_scan(file_path)

            
            if scan_result: 
                 print(f"Threat detected in new process: {scan_result} - {file_path} (PID: {pid})")
                 
                 self.kill_process("Process Threat Intercepted", h_process, file_path)
                 
                 h_process = None 
            else:
                 
                 
                 self.lock_process(h_process, False) 
                 
                 
                 
                 self.track_proc = (h_process, file_path)
                 
                 
                 
                 
                 
                 self.kernel32.CloseHandle(h_process)
                 self.track_proc = (pid, file_path) 
                 h_process = None


        except Exception as e:
            print(f"Error handling new process PID {pid}: {e}")
            
            if h_process:
                try:
                    self.lock_process(h_process, False) 
                except: pass
                try:
                    self.kernel32.CloseHandle(h_process)
                except: pass
            self.track_proc = None 


    def check_whitelist(self, file_or_dir_path):
        """Checks if a given path is within any whitelisted path."""
        try:
            normalized_path = os.path.normpath(file_or_dir_path).lower()
            
            current_whitelist = self.config_json.get("white_lists", [])
            if not isinstance(current_whitelist, list): return False

            for white_item in current_whitelist:
                normalized_white_item = os.path.normpath(white_item).lower()
                
                if normalized_path == normalized_white_item or \
                   normalized_path.startswith(normalized_white_item + os.path.sep):
                    return True
            return False
        except Exception as e:
            print(f"Error checking whitelist for {file_or_dir_path}: {e}")
            return False 


    def kill_process(self, reason, process_pid_or_handle, file_path):
        """Terminates a process identified by PID or handle."""
        pid_to_kill = -1
        handle_to_close = None

        if isinstance(process_pid_or_handle, int): 
            pid_to_kill = process_pid_or_handle
            
            handle_to_close = self.kernel32.OpenProcess(0x0001, False, pid_to_kill) 
        elif hasattr(process_pid_or_handle, 'value'): 
            handle_to_close = process_pid_or_handle
            
            
            
            
        else:
            print(f"Invalid identifier for kill_process: {process_pid_or_handle}")
            return

        try:
            if handle_to_close:
                success = self.kernel32.TerminateProcess(handle_to_close, 1) 
                if success:
                    log_msg = f"{reason}: Terminated process '{os.path.basename(file_path)}'"
                    if pid_to_kill != -1: log_msg += f" (PID: {pid_to_kill})"
                    self.send_notify(log_msg, True)
                else:
                    
                    error_code = ctypes.get_last_error()
                    print(f"Failed to terminate process {file_path} (PID: {pid_to_kill}). Error: {error_code}")
                
                self.kernel32.CloseHandle(handle_to_close)
            else:
                 print(f"Could not get handle to terminate process PID {pid_to_kill}.")

        except Exception as e:
            print(f"Exception during kill_process for {file_path}: {e}")
            
            if handle_to_close:
                 try: self.kernel32.CloseHandle(handle_to_close)
                 except: pass
        finally:
            
             if self.track_proc and isinstance(self.track_proc[0], int) and self.track_proc[0] == pid_to_kill:
                  self.track_proc = None
             elif self.track_proc and self.track_proc[1] == file_path: 
                  self.track_proc = None


    def lock_process(self, h_process, lock): 
        """Suspends (lock=True) or resumes (lock=False) a process using NtSuspendProcess/NtResumeProcess."""
        try:
            if lock:
                result = self.ntdll.NtSuspendProcess(h_process)
                
            else:
                result = self.ntdll.NtResumeProcess(h_process)
                
            
            return result == 0
        except Exception as e:
            print(f"Exception in lock_process (NtSuspend/Resume): {e}")
            return False


    def get_process_file(self, h_process): 
        """Gets the full path of the executable file for a given process handle."""
        if not h_process: return None
        try:
            
            exe_path_buffer = ctypes.create_unicode_buffer(1024)
            buffer_size = ctypes.wintypes.DWORD(1024) 

            if self.kernel32.QueryFullProcessImageNameW(h_process, 0, exe_path_buffer, ctypes.byref(buffer_size)):
                 full_path = exe_path_buffer.value
                 
                 
                 return self._device_path_to_drive_path(full_path)
            else:
                
                fallback_buffer = ctypes.create_unicode_buffer(1024)
                if self.psapi.GetProcessImageFileNameW(h_process, fallback_buffer, 1024) > 0:
                     
                     return self._device_path_to_drive_path(fallback_buffer.value)
                else:
                     
                     return None

        except Exception as e:
            print(f"Exception getting process file path: {e}")
            return None

    def _device_path_to_drive_path(self, device_path):
        """Converts an NT device path (e.g., \\Device\\HarddiskVolumeX\\...) to a drive letter path."""
        if not device_path: return device_path

        
        drive_buffer_len = self.kernel32.GetLogicalDriveStringsW(0, None)
        if drive_buffer_len == 0: return device_path 
        drive_buffer = ctypes.create_unicode_buffer(drive_buffer_len)
        if self.kernel32.GetLogicalDriveStringsW(drive_buffer_len, drive_buffer) == 0:
             return device_path 

        
        drives = [drive for drive in drive_buffer.value.split('\0') if drive]

        
        target_path_buffer = ctypes.create_unicode_buffer(1024)
        for drive in drives:
            drive_letter = drive[:2] 
            
            if self.kernel32.QueryDosDeviceW(drive_letter, target_path_buffer, 1024) != 0:
                 mapped_device = target_path_buffer.value
                 
                 if device_path.startswith(mapped_device):
                      
                      return device_path.replace(mapped_device, drive_letter, 1)

        
        return device_path


    def protect_file_thread(self): 
        """Monitors file system changes using ReadDirectoryChangesW."""
        print("File protection thread started.")
        self.ransom_counts = 0 
        hDir = None 

        
        FILE_LIST_DIRECTORY = 0x0001
        FILE_NOTIFY_CHANGE_FILE_NAME = 0x0001   
        FILE_NOTIFY_CHANGE_DIR_NAME = 0x0002    
        FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x0004
        FILE_NOTIFY_CHANGE_SIZE = 0x0008
        FILE_NOTIFY_CHANGE_LAST_WRITE = 0x0010  
        FILE_NOTIFY_CHANGE_SECURITY = 0x0100

        
        FILE_ACTION_ADDED = 1
        FILE_ACTION_REMOVED = 2
        FILE_ACTION_MODIFIED = 3
        FILE_ACTION_RENAMED_OLD_NAME = 4
        FILE_ACTION_RENAMED_NEW_NAME = 5

        
        
        monitor_flags = (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                         FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE)

        try:
            
            
            
            drive_to_monitor = "C:\\" 
            hDir = self.kernel32.CreateFileW(
                drive_to_monitor,
                FILE_LIST_DIRECTORY,
                0x00000001 | 0x00000002 | 0x00000004, 
                None,                                
                3,                                   
                0x02000000 | 0x00000010,             
                None                                 
            )

            if not hDir or hDir == -1: 
                print(f"Failed to open handle to {drive_to_monitor}. Error: {ctypes.get_last_error()}. File protection disabled.")
                self.config_json["file_protect"] = 0 
                self.init_config_write(self.config_json)
                
                return 

            
            buffer_size = 4096 
            buffer = ctypes.create_string_buffer(buffer_size)
            bytesReturned = ctypes.wintypes.DWORD()

            while self.config_json.get("file_protect", 0) == 1:
                
                success = self.kernel32.ReadDirectoryChangesW(
                    hDir,             
                    ctypes.byref(buffer), 
                    buffer_size,      
                    True,             
                    monitor_flags,    
                    ctypes.byref(bytesReturned), 
                    None,             
                    None              
                )

                if not success:
                     
                     error_code = ctypes.get_last_error()
                     print(f"ReadDirectoryChangesW failed. Error code: {error_code}")
                     if error_code == 6: 
                          print("Directory handle became invalid. Stopping file protection.")
                          break 
                     
                     time.sleep(5)
                     continue

                if bytesReturned.value == 0:
                     
                     continue

                
                offset = 0
                while True: 
                    
                    notify_info = FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)

                    
                    filename_length_bytes = notify_info.FileNameLength
                    filename_offset = FILE_NOTIFY_INFORMATION.FileName.offset
                    
                    filename_ptr = ctypes.addressof(notify_info) + filename_offset
                    
                    raw_filename = ctypes.wstring_at(filename_ptr, filename_length_bytes // 2) 

                    
                    fpath = os.path.join(drive_to_monitor, raw_filename).replace("\\", "/")

                    
                    ftype = os.path.splitext(fpath)[-1].lower()

                    action = notify_info.Action

                    
                    
                    current_tracked_pid = self.track_proc[0] if self.track_proc else None
                    current_tracked_path = self.track_proc[1] if self.track_proc else None

                    
                    suspicious_action = False
                    
                    is_sensitive_area = (":/windows" in fpath.lower() and "/temp/" not in fpath.lower()) or \
                                         (":/users" in fpath.lower() and "/appdata/" not in fpath.lower())

                    if is_sensitive_area and ftype in file_types and action in [FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_OLD_NAME]:
                         suspicious_action = True
                         self.ransom_counts += 1
                         print(f"Suspicious action count: {self.ransom_counts} by PID {current_tracked_pid} on {fpath}")

                    
                    if self.ransom_counts >= 5 and current_tracked_pid:
                        print(f"Ransomware threshold reached by PID {current_tracked_pid} ({current_tracked_path}). Terminating.")
                        self.kill_process("Ransomware Behavior Detected", current_tracked_pid, current_tracked_path)
                        self.ransom_counts = 0 
                        self.track_proc = None 


                    
                    
                    is_user_or_other_area = not (":/windows" in fpath.lower() or \
                                                 ":/program files" in fpath.lower() or \
                                                 ":/program files (x86)" in fpath.lower())

                    if action in [FILE_ACTION_ADDED, FILE_ACTION_MODIFIED] and is_user_or_other_area:
                        
                        if not self.check_whitelist(fpath):
                             
                             if os.path.exists(fpath) and os.path.isfile(fpath):
                                 
                                 scan_result = self.start_scan(fpath)
                                 if scan_result:
                                     print(f"Threat found in new/modified file: {scan_result} - {fpath}")
                                     
                                     try:
                                         self.lock_file(fpath, False) 
                                         os.remove(fpath)
                                         self.send_notify(f"Threat Deleted (File Protect): {os.path.basename(fpath)} ({scan_result})", True)
                                         
                                         if current_tracked_pid:
                                             self.kill_process("File Threat Created", current_tracked_pid, current_tracked_path)
                                             self.track_proc = None
                                     except Exception as del_err:
                                         print(f"Failed to delete detected file {fpath}: {del_err}")


                    
                    if notify_info.NextEntryOffset == 0:
                        break 
                    offset += notify_info.NextEntryOffset 

            

        except Exception as e:
            print(f"Error in file protection thread: {e}")
        finally:
             
             if hDir and hDir != -1:
                 self.kernel32.CloseHandle(hDir)
                 print("Closed directory handle.")
        print("File protection thread stopped.")


    def protect_boot_thread(self): 
        """Monitors the Master Boot Record for changes."""
        if not self.mbr_value:
            print("MBR protection thread not started: Initial MBR read failed or invalid.")
            return

        print("Boot protection thread started.")
        while self.config_json.get("sys_protect", 0) == 1:
            try:
                time.sleep(2) 

                current_mbr = None
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                     current_mbr = f.read(512)

                
                if current_mbr[510:512] != b'\x55\xAA':
                     print("MBR boot signature invalid!")
                     
                     if self.track_proc:
                          pid, path = self.track_proc
                          print(f"Potential MBR tampering (invalid signature) by PID {pid} ({path}). Terminating.")
                          self.kill_process("MBR Tampering Detected (Signature)", pid, path)
                          self.track_proc = None
                     
                     

                
                elif current_mbr != self.mbr_value:
                    print("MBR change detected!")
                    
                    pid_responsible = -1
                    path_responsible = "Unknown"
                    if self.track_proc:
                         pid_responsible, path_responsible = self.track_proc
                         print(f"Potential MBR tampering by PID {pid_responsible} ({path_responsible}).")
                         self.kill_process("MBR Tampering Detected (Content)", pid_responsible, path_responsible)
                         self.track_proc = None

                    
                    if self.question_event(f"MBR has been modified (potentially by PID {pid_responsible}). Restore original MBR?"):
                         try:
                              with open(r"\\.\PhysicalDrive0", "r+b") as f:
                                   f.seek(0)
                                   f.write(self.mbr_value)
                              self.send_notify("MBR restored to original state.", True)
                         except Exception as restore_err:
                              print(f"Failed to restore MBR: {restore_err}")
                              self.send_notify("Failed to restore MBR!", True)
                    

                

            except PermissionError:
                print("Permission denied accessing PhysicalDrive0 in boot protect thread. Stopping.")
                self.config_json["sys_protect"] = 0 
                self.init_config_write(self.config_json)
                
                break
            except Exception as e:
                print(f"Error in boot protection thread: {e}")
                time.sleep(5) 

        print("Boot protection thread stopped.")


    def protect_reg_thread(self): 
        """Periodically runs registry repair functions if System Protection is enabled."""
        print("Registry protection thread started.")
        while self.config_json.get("sys_protect", 0) == 1:
            try:
                
                
                time.sleep(300) 

                print("Performing periodic registry check/repair...")
                
                
                self.repair_system_image()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                
                
                print("Periodic registry check/repair complete.")

            except Exception as e:
                print(f"Error in registry protection thread: {e}")
                time.sleep(60) 
        print("Registry protection thread stopped.")


    def get_connections_list(self):  
        """Returns a set of active TCP connections: {(PID, LocalAddr, RemoteAddr, State), ...}"""
        try:
            connections = set()
            dwSize = ctypes.wintypes.DWORD(0)
            AF_INET = 2 
            TCP_TABLE_OWNER_PID_ALL = 5 

            
            ret = self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

            
            if ret != 122:
                print(f"Error getting TCP table size: {ctypes.WinError(ret)} ({ret})")
                return None 

            
            
            if dwSize.value == 0:
                 print("TCP table size reported as 0. No connections or error.")
                 return set() 

            lpTcpTable = ctypes.create_string_buffer(dwSize.value)

            
            ret = self.iphlpapi.GetExtendedTcpTable(ctypes.byref(lpTcpTable), ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

            if ret != 0: 
                print(f"Error getting TCP table data: {ctypes.WinError(ret)} ({ret})")
                return None

            
            
            num_entries = ctypes.cast(lpTcpTable, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            
            offset = ctypes.sizeof(ctypes.wintypes.DWORD)
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)

            for i in range(num_entries):
                entry_address = ctypes.addressof(lpTcpTable) + offset + (i * row_size)
                conn_entry = ctypes.cast(entry_address, ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents

                
                connections.add((
                    conn_entry.dwOwningPid,
                    conn_entry.dwLocalAddr,   
                    conn_entry.dwRemoteAddr,  
                    conn_entry.dwState       
                ))

            return connections

        except Exception as e:
            print(f"Exception getting connections list: {e}")
            return None


    def protect_net_thread(self): 
        """Monitors for new network connections and checks against blocklists."""
        print("Network protection thread started.")
        while self.config_json.get("net_protect", 0) == 1:
            try:
                time.sleep(1) 
                current_connections = self.get_connections_list()
                if current_connections is None: continue 

                
                new_conns = current_connections - self.exist_connections

                if new_conns:
                    
                    for conn_key in new_conns:
                        
                        
                        
                        if conn_key[3] == 5: 
                             self.handle_new_connection(conn_key)

                
                self.exist_connections = current_connections

            except Exception as e:
                print(f"Error in network protection thread: {e}")
                time.sleep(5) 
        print("Network protection thread stopped.")


    def handle_new_connection(self, conn_key): 
        """Checks the process and remote IP of a new connection against rules/blocklists."""
        pid, local_addr_int, remote_addr_int, state = conn_key
        h_process = None 

        
        if remote_addr_int == 0x0100007F:
            return

        
        
        remote_ip_str = f"{remote_addr_int & 0xFF}.{(remote_addr_int >> 8) & 0xFF}.{(remote_addr_int >> 16) & 0xFF}.{(remote_addr_int >> 24) & 0xFF}"

        try:
            
            
            access_flags = 0x1000 | 0x0400 | 0x0001 
            h_process = self.kernel32.OpenProcess(access_flags, False, pid)
            if not h_process: return 

            
            file_path = self.get_process_file(h_process)
            if not file_path or not os.path.exists(file_path):
                self.kernel32.CloseHandle(h_process)
                return

            file_path = file_path.replace("\\", "/")

            
            if self.check_whitelist(file_path):
                self.kernel32.CloseHandle(h_process)
                return

            
            
            
            blocked_ips = getattr(self.rules, 'network', set()) 
            if remote_ip_str in blocked_ips:
                 print(f"Blocked network connection: {file_path} (PID: {pid}) -> {remote_ip_str}")
                 
                 self.kill_process(f"Blocked Network Connection ({remote_ip_str})", pid, file_path)
                 
                 h_process = None 
            

            
            if h_process:
                self.kernel32.CloseHandle(h_process)

        except Exception as e:
            print(f"Error handling new connection for PID {pid} to {remote_ip_str}: {e}")
            if h_process: 
                 try: self.kernel32.CloseHandle(h_process)
                 except: pass



if __name__ == '__main__': 
    
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    
    QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    
    app = QApplication(sys.argv)

    
    
    main_window = MainWindow_Controller()

    
    sys.exit(app.exec_())
