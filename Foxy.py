import os, gc, sys, time, json
import ctypes, ctypes.wintypes
import requests, msvcrt, pyperclip
from Foxy_Engine import YRScan, DLScan
from PYAS_Suffixes import file_types
# Removed: from PYAS_Language import translate_dict # No longer needed
from Foxy_Interface import Ui_MainWindow
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from subprocess import *
from threading import *

class PROCESSENTRY32(ctypes.Structure): # Initialize definition
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

class MainWindow_Controller(QMainWindow): # Initialize main program
    def __init__(self): # Initialize call
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.init_config_pyas() # Initialize program

    def init_config_pyas(self):
        self.init_config_vars() # Initialize variables
        self.init_config_path() # Initialize paths
        self.init_config_read() # Initialize configuration
        self.init_config_wdll() # Initialize system components
        self.init_config_boot() # Initialize boot sector check
        self.init_config_list() # Initialize lists (processes, connections)
        self.init_config_data() # Initialize engine data (models, rules)
        self.init_config_icon() # Initialize tray icon
        self.init_config_qtui() # Initialize UI interface
        self.init_config_color() # Initialize colors/theme
        self.init_config_conn() # Initialize connections (signals/slots)
        self.init_config_lang() # Initialize language settings (though translation is removed)
        self.init_config_func() # Initialize core functions/protections
        self.init_config_done() # Mark initialization as complete
        self.init_config_theme() # Initialize theme application

    def init_config_vars(self): # Initialize variables
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
        "language_ui": "en_US",  # Language setting (though translation removed, kept for structure)
        "theme_color": "White",  # "Solid color" or "./Theme/Path"
        "product_key": "None",   # "None" or "XXXXX-X..."
        "service_url": "None",   # "None" or "http://..."
        "proc_protect": 1, # "0" (Close), "1" (Open)
        "file_protect": 1, # "0" (Close), "1" (Open)
        "sys_protect": 1,  # "0" (Close), "1" (Open)
        "net_protect": 1,  # "0" (Close), "1" (Open)
        "cus_protect": 0,  # "0" (Close), "1" (Open) - Custom protection
        "sensitivity": 0,  # "0" (Medium), "1" (High)
        "extend_mode": 0,  # "0" (False), "1" (True) - Extended engine mode
        "white_lists": [], # Whitelisted paths
        "block_lists": []  # Blocked window definitions
        }
        self.pass_windows = [ # Windows to ignore for blocking
        {'': ''}, {'PYAS': 'Qt5152QWindowIcon'},
        {'': 'Shell_TrayWnd'}, {'': 'WorkerW'}]

    def init_config_path(self): # Initialize paths
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

    def reset_options(self): # Reset all settings
        if self.question_event("Are you sure you want to reset all settings?"):
            self.clean_function()
            self.config_json = self.default_json
            self.init_config_write(self.config_json)
            self.init_config_pyas()

    def clean_function(self): # Clean up running functions
        self.first_startup = 1
        self.block_window = 0
        self.config_json["proc_protect"] = 0
        self.config_json["file_protect"] = 0
        self.config_json["sys_protect"] = 0
        self.config_json["net_protect"] = 0
        self.virus_scan_break()
        self.protect_drv_init(stop_only=True) # Try to stop driver without prompt on reset
        self.gc_collect = 0

    def init_config_read(self): # Initialize configuration reading
        try:
            self.config_json = {}
            if not os.path.exists(self.path_conf):
                os.makedirs(self.path_conf)
            if not os.path.exists(self.file_conf):
                 # If config doesn't exist, write default values
                self.config_json = self.default_json.copy()
                self.init_config_write(self.config_json)
            else:
                with open(self.file_conf, "r") as f:
                    self.config_json = json.load(f)

            # Ensure all keys exist, using defaults if missing
            for key, default_value in self.default_json.items():
                self.config_json[key] = self.config_json.get(key, default_value)

        except Exception as e:
            print(f"Error reading config: {e}")
            # Fallback to default if reading fails critically
            self.config_json = self.default_json.copy()
            self.init_config_write(self.config_json)


    def init_config_write(self, config): # Write configuration
        try:
            with open(self.file_conf, "w") as f:
                # Use ensure_ascii=False only if you NEED non-ASCII chars in JSON, otherwise True is safer
                f.write(json.dumps(config, indent=4, ensure_ascii=True))
        except Exception as e:
            print(e)

    def init_config_wdll(self): # Initialize system DLLs
        try:
            self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            self.psapi = ctypes.WinDLL('Psapi', use_last_error=True)
            self.user32 = ctypes.WinDLL('user32', use_last_error=True)
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            self.iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
        except Exception as e:
            print(e)

    def init_config_boot(self): # Initialize boot sector check
        try:
            # Use 'with' statement for proper file handling
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                self.mbr_value = f.read(512)
            # Check the boot signature
            if self.mbr_value[510:512] != b'\x55\xAA':
                self.mbr_value = None # Invalid MBR
        except PermissionError:
            print("Permission denied reading PhysicalDrive0. Run as Administrator.")
            self.mbr_value = None
        except Exception as e:
            print(f"Error reading MBR: {e}")
            self.mbr_value = None

    def init_config_list(self): # Initialize lists
        try:
            self.exist_process = self.get_process_list()
            self.exist_connections = self.get_connections_list()
        except Exception as e:
            print(e)

    def init_config_data(self): # Initialize engine data
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

    def init_config_icon(self): # Initialize tray icon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.activated.connect(self.init_config_show)
        # Set icon from the application's executable file
        self.tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(self.path_pyas)))
        self.tray_icon.show()

    def init_config_qtui(self): # Initialize UI interface
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.Process_sim = QStringListModel()
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.process_list)

        # Layering UI elements
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()

        # Shadows for depth effect
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

        # Initial widget visibility
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_widget.hide()
        self.ui.Tools_widget.hide()
        self.ui.Protection_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Process_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()

        # Polish scrollbars (apply style)
        self.ui.State_output.style().polish(self.ui.State_output.verticalScrollBar())
        self.ui.Virus_Scan_output.style().polish(self.ui.Virus_Scan_output.verticalScrollBar())

        # Set license text
        self.ui.License_terms.setText('''MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')

    def init_config_conn(self): # Initialize connections (signals/slots)
        # Window controls
        self.ui.Close_Button.clicked.connect(self.close)
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.show_menu) # Consider renaming show_about_menu if that's all it does

        # Navigation buttons
        self.ui.State_Button.clicked.connect(self.change_state_widget)
        self.ui.Tools_Button.clicked.connect(self.change_tools_widget)
        self.ui.Virus_Scan_Button.clicked.connect(self.change_scan_widget)
        self.ui.Protection_Button.clicked.connect(self.change_protect_widget)
        self.ui.Setting_Button.clicked.connect(self.change_setting_widget)

        # Virus Scan specific
        self.ui.Virus_Scan_output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Virus_Scan_output.customContextMenuRequested.connect(self.Virus_Scan_output_menu)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)

        # Tools specific
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.change_tools(self.ui.Process_widget))
        self.ui.Repair_System_Files_Button.clicked.connect(self.repair_system)
        self.ui.Clean_System_Files_Button.clicked.connect(self.clean_system)
        self.ui.Window_Block_Button.clicked.connect(self.add_software_window)
        self.ui.Window_Block_Button_2.clicked.connect(self.remove_software_window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.repair_network)
        self.ui.Reset_Options_Button.clicked.connect(self.reset_options)

        # Process list specific
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.process_list_menu)

        # Protection toggles
        self.ui.Protection_switch_Button.clicked.connect(self.protect_proc_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_file_init)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_sys_init)
        self.ui.Protection_switch_Button_4.clicked.connect(lambda: self.protect_drv_init(stop_only=False)) # Pass default arg
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_net_init)
        self.ui.Protection_switch_Button_8.clicked.connect(self.protect_cus_init)

        # Settings toggles
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.change_sensitive)
        self.ui.extension_kit_switch_Button.clicked.connect(self.extension_kit)
        self.ui.cloud_services_switch_Button.clicked.connect(self.cloud_services)

        # Whitelist buttons
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Add_White_list_Button_3.clicked.connect(self.remove_white_list)

        # Language selection (Kept for UI logic, but doesn't trigger translation)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_English.clicked.connect(self.init_change_lang)

        # Theme selection
        self.ui.Theme_White.clicked.connect(self.init_change_theme)
        self.ui.Theme_Customize.clicked.connect(self.init_change_theme)
        self.ui.Theme_Green.clicked.connect(self.init_change_theme)
        self.ui.Theme_Yellow.clicked.connect(self.init_change_theme)
        self.ui.Theme_Blue.clicked.connect(self.init_change_theme)
        self.ui.Theme_Red.clicked.connect(self.init_change_theme)

    def init_config_lang(self): # Initialize language selection UI
        try:
            # Set radio button based on config, default to English if key missing
            lang = self.config_json.get("language_ui", "en_US")
            if lang == "zh_TW":
                self.ui.Language_Traditional_Chinese.setChecked(True)
            elif lang == "zh_CN":
                self.ui.Language_Simplified_Chinese.setChecked(True)
            else: # Default to English
                self.ui.Language_English.setChecked(True)
            self.init_change_text() # Apply static English text
        except Exception as e:
            print(e)

    def init_change_lang(self): # Update config based on language selection
        try:
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_TW"
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_CN"
            elif self.ui.Language_English.isChecked():
                self.config_json["language_ui"] = "en_US"
            # No need to call init_change_text() here as text is static English now
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    # Removed the trans(self, text) method as requested

    def init_change_text(self): # Set all UI text elements to static English
        # --- Status Page ---
        self.ui.State_title.setText("This device is protected")
        self.ui.State_log.setText("Log:")

        # --- Window ---
        self.ui.Window_title.setText("Foxy Security")
        self.ui.PYAS_CopyRight.setText(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} Foxy Security")

        # --- Virus Scan Page ---
        self.ui.Virus_Scan_title.setText("Virus Scan")
        self.ui.Virus_Scan_text.setText("Please select a scan method")
        self.ui.Virus_Scan_choose_Button.setText("Virus Scan") # Button that opens scan type menu
        self.ui.File_Scan_Button.setText("File Scan")
        self.ui.Path_Scan_Button.setText("Path Scan")
        self.ui.Disk_Scan_Button.setText("Full Scan")
        self.ui.Virus_Scan_Solve_Button.setText("Delete Now")
        self.ui.Virus_Scan_Break_Button.setText("Stop Scan")

        # --- Process Manager Page (accessible from Tools) ---
        self.ui.Process_Total_title.setText("Total Processes:")
        # Process_Total_View is the number display, no static text needed

        # --- Protection Page ---
        # Process Protection
        self.ui.Protection_title.setText("Process Protection")
        self.ui.Protection_illustrate.setText("Enable this option to intercept process viruses")
        # Set button text based on actual state later in init_config_color or toggles
        self.ui.Protection_switch_Button.setText("Disabled") # Default state text

        # File Protection
        self.ui.Protection_title_2.setText("File Protection")
        self.ui.Protection_illustrate_2.setText("Enable this option to monitor file changes")
        self.ui.Protection_switch_Button_2.setText("Disabled")

        # System Protection
        self.ui.Protection_title_3.setText("System Protection")
        self.ui.Protection_illustrate_3.setText("Enable this option to repair system items")
        self.ui.Protection_switch_Button_3.setText("Disabled")

        # Driver Protection
        self.ui.Protection_title_4.setText("Driver Protection")
        self.ui.Protection_illustrate_4.setText("Enable this option to enhance self-protection")
        self.ui.Protection_switch_Button_4.setText("Disabled")

        # Network Protection
        self.ui.Protection_title_5.setText("Network Protection")
        self.ui.Protection_illustrate_5.setText("Enable this option to monitor network communications")
        self.ui.Protection_switch_Button_5.setText("Disabled")

        # Custom Protection (Marked as unsupported later)
        self.ui.Protection_title_8.setText("Custom Protection")
        self.ui.Protection_illustrate_8.setText("Enable this option to select custom protection")
        self.ui.Protection_switch_Button_8.setText("Disabled")

        # --- Tools Page ---
        # Process Management
        self.ui.System_Process_Manage_title.setText("Process Management")
        self.ui.System_Process_Manage_illustrate.setText("This option allows real-time viewing of system processes")
        self.ui.System_Process_Manage_Button.setText("Select")

        # Junk Clean
        self.ui.Clean_System_Files_title.setText("Junk Clean")
        self.ui.Clean_System_Files_illustrate.setText("This option can clean temporary files")
        self.ui.Clean_System_Files_Button.setText("Select")

        # System Repair
        self.ui.Repair_System_Files_title.setText("System Repair")
        self.ui.Repair_System_Files_illustrate.setText("This option can repair system registry entries")
        self.ui.Repair_System_Files_Button.setText("Select")

        # Network Repair
        self.ui.Repair_System_Network_title.setText("Network Repair")
        self.ui.Repair_System_Network_illustrate.setText("This option can reset system network connections")
        self.ui.Repair_System_Network_Button.setText("Select")

        # Reset Options
        self.ui.Reset_Options_title.setText("Reset Options")
        self.ui.Reset_Options_illustrate.setText("This option can reset all setting options")
        self.ui.Reset_Options_Button.setText("Select")

        # Window Blocking
        self.ui.Window_Block_title.setText("Popup Blocking")
        self.ui.Window_Block_illustrate.setText("This option allows selecting specific windows to block")
        self.ui.Window_Block_Button.setText("Add")
        self.ui.Window_Block_Button_2.setText("Remove")

        # --- About Page ---
        self.ui.PYAS_Version.setText(f"Foxy Security V{self.pyas_version} ({self.pyae_version})")
        self.ui.GUI_Made_title.setText("Interface Design:")
        self.ui.GUI_Made_Name.setText("mtkiao")
        self.ui.Core_Made_title.setText("Core Development:")
        self.ui.Core_Made_Name.setText("87owo")
        self.ui.Testers_title.setText("Special Thanks:")
        self.ui.Testers_Name.setText("0sha0") # Assuming this is a name/handle
        self.ui.PYAS_URL_title.setText("Official Website:")
        self.ui.PYAS_URL.setText("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>")
        self.ui.License_terms_title.setText("License Terms:")

        # --- Settings Page ---
        # High Sensitivity
        self.ui.high_sensitivity_title.setText("High Sensitivity Mode")
        self.ui.high_sensitivity_illustrate.setText("Enable this option to increase scan engine sensitivity")
        self.ui.high_sensitivity_switch_Button.setText("Disabled") # Default state text

        # Extension Kit
        self.ui.extension_kit_title.setText("Extended Scan Engine")
        self.ui.extension_kit_illustrate.setText("Enable this option to use third-party extension kits")
        self.ui.extension_kit_switch_Button.setText("Disabled")

        # Cloud Services (Marked as unsupported later)
        self.ui.cloud_services_title.setText("Cloud Scan Service")
        self.ui.cloud_services_illustrate.setText("Enable this option to connect to cloud scanning services")
        self.ui.cloud_services_switch_Button.setText("Disabled")

        # Whitelist Management
        self.ui.Add_White_list_title.setText("Add to Whitelist")
        self.ui.Add_White_list_illustrate.setText("This option allows selecting files/folders to add to the whitelist")
        self.ui.Add_White_list_Button.setText("Add")
        self.ui.Add_White_list_Button_3.setText("Remove")

        # Theme Selection
        self.ui.Theme_title.setText("Display Theme")
        self.ui.Theme_illustrate.setText("Please select a theme")
        self.ui.Theme_Customize.setText("Custom Theme")
        self.ui.Theme_White.setText("White Theme")
        self.ui.Theme_Yellow.setText("Yellow Theme")
        self.ui.Theme_Red.setText("Red Theme")
        self.ui.Theme_Green.setText("Green Theme")
        self.ui.Theme_Blue.setText("Blue Theme")

        # Language Selection
        self.ui.Language_title.setText("Display Language")
        self.ui.Language_illustrate.setText("Please select a language")
        # Radio button text is set directly in Qt Designer or here if needed
        # self.ui.Language_Traditional_Chinese.setText("Traditional Chinese")
        # self.ui.Language_Simplified_Chinese.setText("Simplified Chinese")
        # self.ui.Language_English.setText("English")

        # Set initial button states based on config (will be refined in init_config_color/theme)
        self._update_button_texts_from_config()


    def _update_button_texts_from_config(self):
        """Helper to set initial button texts based on config values."""
        self.ui.Protection_switch_Button.setText("Enabled" if self.config_json.get("proc_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_2.setText("Enabled" if self.config_json.get("file_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_3.setText("Enabled" if self.config_json.get("sys_protect", 0) else "Disabled")
        # Driver protection text depends on service status, handled in protect_drv_init
        self.ui.Protection_switch_Button_5.setText("Enabled" if self.config_json.get("net_protect", 0) else "Disabled")
        self.ui.Protection_switch_Button_8.setText("Enabled" if self.config_json.get("cus_protect", 0) else "Disabled")
        self.ui.high_sensitivity_switch_Button.setText("Enabled" if self.config_json.get("sensitivity", 0) else "Disabled")
        self.ui.extension_kit_switch_Button.setText("Enabled" if self.config_json.get("extend_mode", 0) else "Disabled")
        self.ui.cloud_services_switch_Button.setText("Enabled" if self.config_json.get("service_url", "None") != "None" else "Disabled") # Assuming "None" means disabled


    def init_config_color(self): # Define theme colors and styles
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
        "Red": {"color": "Red", "icon": ":/icon/Check.png", # Consider a different icon for non-white themes?
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
        # Call the function to apply the theme based on current config
        # self.init_change_color() # Moved call to init_config_theme

    def init_config_theme(self): # Initialize theme selection UI and apply theme
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
            elif os.path.exists(theme_name): # Check if it's a path for custom theme
                 self.ui.Theme_Customize.setChecked(True)
            else: # Default to White if value is invalid
                self.config_json["theme_color"] = "White"
                self.ui.Theme_White.setChecked(True)

            self.init_change_color() # Apply the loaded/selected theme colors
        except Exception as e:
            print(f"Error initializing theme UI: {e}")
            self.config_json["theme_color"] = "White" # Fallback
            self.ui.Theme_White.setChecked(True)
            self.init_change_color()


    def init_change_theme(self): # Change theme based on UI interaction
        try:
            new_theme_value = "White" # Default
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
                # Ask user for custom theme path if not already set or invalid
                current_theme_path = self.config_json.get("theme_color", "")
                if not os.path.exists(os.path.join(current_theme_path, "Color.json")):
                     path = str(QFileDialog.getExistingDirectory(self, "Select Custom Theme Folder", ""))
                     if path and os.path.exists(os.path.join(path, "Color.json")):
                         new_theme_value = path
                     else:
                         # Revert to White theme if custom selection fails
                         self.ui.Theme_White.setChecked(True)
                         new_theme_value = "White"
                         self.info_event("Invalid custom theme folder selected. Reverted to White theme.")
                else:
                    # Keep existing valid custom path
                    new_theme_value = current_theme_path

            # Update config only if the theme actually changed
            if self.config_json.get("theme_color") != new_theme_value:
                 self.config_json["theme_color"] = new_theme_value
                 self.init_config_write(self.config_json)
                 self.init_change_color() # Apply the new theme

        except Exception as e:
            print(f"Error changing theme: {e}")


    def init_change_color(self): # Apply color styles based on the selected theme
        try:
            theme_name_or_path = self.config_json.get("theme_color", "White")
            self.theme = None # Reset theme data

            if theme_name_or_path in self.config_theme:
                # Load predefined theme
                self.theme = self.config_theme[theme_name_or_path]
                self.ui.State_icon.setPixmap(QPixmap(self.theme["icon"]))
            else:
                # Attempt to load custom theme from path
                custom_theme_path = theme_name_or_path
                color_json_path = os.path.join(custom_theme_path, "Color.json")
                icon_path_relative = "" # Placeholder

                if os.path.exists(color_json_path):
                    try:
                        with open(color_json_path, "r") as f:
                            self.theme = json.load(f)
                        # Validate essential keys exist in custom theme JSON
                        required_keys = ["icon", "button_on", "button_off", "widget_style", "window_style", "navigation_style"]
                        if not all(key in self.theme for key in required_keys):
                             raise ValueError("Custom theme JSON missing required keys.")

                        icon_path_relative = self.theme.get("icon", "")
                        icon_full_path = os.path.join(custom_theme_path, icon_path_relative)

                        if os.path.exists(icon_full_path):
                            self.ui.State_icon.setPixmap(QPixmap(icon_full_path))
                        else:
                            # Fallback icon if custom icon not found
                            print(f"Warning: Custom theme icon not found at {icon_full_path}. Using default.")
                            self.ui.State_icon.setPixmap(QPixmap(self.config_theme["White"]["icon"]))

                    except (json.JSONDecodeError, ValueError, Exception) as load_err:
                        print(f"Error loading custom theme from {custom_theme_path}: {load_err}")
                        self.theme = None # Invalidate theme on error
                else:
                     print(f"Custom theme path or Color.json not found: {theme_name_or_path}")
                     self.theme = None # Invalidate theme

            # Fallback to White theme if custom loading failed or theme is invalid
            if self.theme is None:
                print("Falling back to White theme.")
                self.theme = self.config_theme["White"]
                self.config_json["theme_color"] = "White" # Correct config if it was invalid
                self.ui.Theme_White.setChecked(True) # Update UI selection
                self.init_config_write(self.config_json) # Save corrected config
                self.ui.State_icon.setPixmap(QPixmap(self.theme["icon"]))

            # --- Apply Styles ---
            self.ui.Window_widget.setStyleSheet(self.theme["window_style"])
            self.ui.Navigation_Bar.setStyleSheet(self.theme["navigation_style"])
            # Apply to main content widgets
            self.ui.State_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Virus_Scan_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Tools_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Process_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Protection_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Setting_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.About_widget.setStyleSheet(self.theme["widget_style"])
            # Apply to the base widget if necessary (widget_2 seems like a background layer)
            self.ui.widget_2.setStyleSheet(self.theme["widget_style"])

            # --- Apply Button Styles ---
            # Apply general button styles first
            self.ui.Virus_Scan_choose_Button.setStyleSheet(self.theme["button_on"]) # Scan button is usually prominent
            self.ui.Add_White_list_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Add_White_list_Button_3.setStyleSheet(self.theme["button_off"])
            self.ui.System_Process_Manage_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Clean_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Reset_Options_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button_2.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Network_Button.setStyleSheet(self.theme["button_off"])

            # Apply specific styles for toggle buttons based on their state ("Enabled"/"Disabled" text)
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
            # Attempt a hard reset to White theme if something goes very wrong
            try:
                self.theme = self.config_theme["White"]
                self.config_json["theme_color"] = "White"
                self.init_config_write(self.config_json)
                # Reapply styles for white theme
                self.init_change_color()
            except:
                 print("Failed to recover theme. UI might look incorrect.")


    def _apply_toggle_button_style(self, button):
        """Helper to apply on/off style based on button text."""
        if button.text() == "Enabled":
            button.setStyleSheet(self.theme["button_on"])
        else: # Assumes "Disabled" or other text means off
            button.setStyleSheet(self.theme["button_off"])


    def init_config_done(self): # Mark initialization complete and show window
        try:
            # Handle command line arguments (e.g., for startup behavior)
            show_window = True
            if len(sys.argv) > 1:
                param = sys.argv[1].replace("/", "-")
                if "-h" in param or "-hidden" in param: # Example: start hidden
                    show_window = False
                # Add other parameter handling if needed

            if show_window:
                self.init_config_show() # Fade in the window

            self.first_startup = 0 # Mark that initial setup is done
        except Exception as e:
            print(f"Error in init_config_done: {e}")

    def init_config_func(self): # Initialize core functional components/protections based on config
        try:
             # Update button texts to reflect config before applying styles/starting threads
            self._update_button_texts_from_config()
            # Apply theme colors based on potentially updated button texts
            self.init_change_color()

            # Start protection threads based on config values
            if self.config_json.get("proc_protect", 0) == 1:
                Thread(target=self.protect_proc_thread, daemon=True).start()
            if self.config_json.get("file_protect", 0) == 1:
                Thread(target=self.protect_file_thread, daemon=True).start()
            if self.config_json.get("sys_protect", 0) == 1:
                Thread(target=self.protect_boot_thread, daemon=True).start()
                Thread(target=self.protect_reg_thread, daemon=True).start()
            if self.config_json.get("net_protect", 0) == 1:
                Thread(target=self.protect_net_thread, daemon=True).start()

            # Initialize driver state (checks if driver should be running)
            self.protect_drv_init(stop_only=False, initial_check=True)

            # Initialize other features
            self.block_window_init() # Start window blocking if enabled/configured
            self.gc_collect_init()   # Start garbage collection thread

        except Exception as e:
            print(f"Error initializing core functions: {e}")


    def protect_proc_init(self): # Initialize/Toggle Process Protection
        try:
            # Check current state based on button text
            if self.ui.Protection_switch_Button.text() == "Enabled":
                # Turn OFF
                self.config_json["proc_protect"] = 0
                self.ui.Protection_switch_Button.setText("Disabled")
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_off"])
                # The thread will stop itself by checking config_json["proc_protect"]
            else:
                # Turn ON
                self.config_json["proc_protect"] = 1
                Thread(target=self.protect_proc_thread, daemon=True).start()
                self.ui.Protection_switch_Button.setText("Enabled")
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_on"])

            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_file_init(self): # Initialize/Toggle File Protection
        try:
            if self.ui.Protection_switch_Button_2.text() == "Enabled":
                # Turn OFF
                self.config_json["file_protect"] = 0
                self.ui.Protection_switch_Button_2.setText("Disabled")
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_off"])
            else:
                # Turn ON
                self.config_json["file_protect"] = 1
                Thread(target=self.protect_file_thread, daemon=True).start()
                self.ui.Protection_switch_Button_2.setText("Enabled")
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_sys_init(self): # Initialize/Toggle System Protection (Boot + Registry)
        try:
            if self.ui.Protection_switch_Button_3.text() == "Enabled":
                # Turn OFF
                self.config_json["sys_protect"] = 0
                self.ui.Protection_switch_Button_3.setText("Disabled")
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_off"])
            else:
                # Turn ON
                self.config_json["sys_protect"] = 1
                # Start threads only if MBR was read successfully for boot protection
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


    def protect_drv_init(self, stop_only=False, initial_check=False): # Initialize/Toggle Driver Protection
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
                 #print(f"Driver install/uninstall scripts not found in {file_path}")
                 self.ui.Protection_switch_Button_4.setText("Unavailable") # Indicate driver can't be managed
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                 self.ui.Protection_switch_Button_4.setEnabled(False) # Disable the button
                 return

            # Check current service status using 'sc query' for better reliability
            try:
                query_result = Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True)
                stdout, stderr = query_result.communicate()
                is_running = "RUNNING" in stdout
                is_stopped = "STOPPED" in stdout
                service_exists = "1060" not in stderr # Error 1060: Service does not exist

                # --- Initial Check Logic ---
                if initial_check:
                    if is_running:
                         self.ui.Protection_switch_Button_4.setText("Enabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                    else:
                         self.ui.Protection_switch_Button_4.setText("Disabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                    return # Don't proceed with start/stop logic during initial check

                # --- Stop Logic ---
                if self.ui.Protection_switch_Button_4.text() == "Enabled" or stop_only:
                     if is_running:
                         # Attempt to stop the service
                         stop_cmd = f'sc stop {service_name}'
                         stop_result = Popen(stop_cmd, shell=True, stdout=PIPE, stderr=PIPE).wait()

                         if stop_result == 0 or "STOP_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                             # Optionally ask to uninstall ONLY if triggered by user click (not stop_only/first_startup)
                             if not self.first_startup and not stop_only and os.path.exists(uninstaller_bat_path):
                                 if self.question_event("Driver protection stopped. Do you want to uninstall the driver? (Requires restart)"):
                                     Popen(f'"{uninstaller_bat_path}"', shell=True, stdout=PIPE, stderr=PIPE)
                                     # User needs to restart manually
                                     self.info_event("Please restart your computer to complete driver uninstallation.")
                                     # Update UI immediately, assuming uninstall is requested
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                                 else:
                                     # User chose not to uninstall, keep service stopped
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                             else:
                                 # Just update UI if stopped via stop_only or during startup
                                 self.ui.Protection_switch_Button_4.setText("Disabled")
                                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                         else:
                             self.info_event(f"Failed to stop driver service (Error code: {stop_result}). Manual check may be needed.")
                             # Keep UI as Enabled if stop failed
                     elif is_stopped and not stop_only:
                         # Already stopped, update UI if clicked
                         self.ui.Protection_switch_Button_4.setText("Disabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                     elif not service_exists and not stop_only:
                          # Service doesn't exist, ensure UI is Disabled
                          self.ui.Protection_switch_Button_4.setText("Disabled")
                          self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                     # If stop_only, no need for further action if already stopped or non-existent

                # --- Start Logic ---
                elif self.ui.Protection_switch_Button_4.text() == "Disabled" and not stop_only:
                     if not service_exists:
                         # Install and start
                         if self.question_event("This option may conflict with other software and requires installing a driver. Are you sure you want to enable it? (Requires restart)"):
                             # Ensure previous instances are removed if necessary
                             Popen(f'sc delete {service_name}', shell=True, stdout=PIPE, stderr=PIPE).wait()
                             install_result = Popen(f'"{driver_bat_path}"', shell=True, stdout=PIPE, stderr=PIPE).wait()
                             if install_result == 0:
                                 # Try starting after install
                                 start_result = Popen(f'sc start {service_name}', shell=True, stdout=PIPE, stderr=PIPE).wait()
                                 if start_result == 0 or "START_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                                     self.info_event("Driver installed and started successfully. A restart is recommended.")
                                     self.ui.Protection_switch_Button_4.setText("Enabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                                 else:
                                     self.info_event(f"Driver installed, but failed to start (Error code: {start_result}). Please restart your computer.")
                                     # Keep UI as disabled, as start failed
                                     self.ui.Protection_switch_Button_4.setText("Disabled")
                                     self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                             else:
                                 self.info_event(f"Driver installation failed (Error code: {install_result}).")
                                 # Keep UI disabled
                         # else: User cancelled install prompt, do nothing to UI
                     elif is_stopped:
                         # Service exists but is stopped, just start it
                         start_cmd = f'sc start {service_name}'
                         start_result = Popen(start_cmd, shell=True, stdout=PIPE, stderr=PIPE).wait()
                         if start_result == 0 or "START_PENDING" in Popen(f'sc query {service_name}', shell=True, stdout=PIPE, stderr=PIPE, text=True).communicate()[0]:
                              self.ui.Protection_switch_Button_4.setText("Enabled")
                              self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
                         else:
                              self.info_event(f"Failed to start existing driver service (Error code: {start_result}). It might require reinstallation or a restart.")
                              # Keep UI as disabled if start failed
                     elif is_running:
                         # Already running, ensure UI is correct (shouldn't happen if logic is right)
                         self.ui.Protection_switch_Button_4.setText("Enabled")
                         self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])

            except FileNotFoundError:
                 print("Error: 'sc' command not found. Driver management requires Windows.")
                 self.ui.Protection_switch_Button_4.setText("Unavailable")
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                 self.ui.Protection_switch_Button_4.setEnabled(False)
            except Exception as e:
                 print(f"Error managing driver protection: {e}")
                 # Attempt to set a reasonable default state on error
                 self.ui.Protection_switch_Button_4.setText("Error")
                 self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])

        except Exception as e:
            print(f"General error in protect_drv_init: {e}")


    def protect_net_init(self): # Initialize/Toggle Network Protection
        try:
            if self.ui.Protection_switch_Button_5.text() == "Enabled":
                # Turn OFF
                self.config_json["net_protect"] = 0
                self.ui.Protection_switch_Button_5.setText("Disabled")
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_off"])
            else:
                # Turn ON
                self.config_json["net_protect"] = 1
                Thread(target=self.protect_net_thread, daemon=True).start()
                self.ui.Protection_switch_Button_5.setText("Enabled")
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_cus_init(self): # Initialize/Toggle Custom Protection (Marked as unsupported)
        self.info_event("This feature is not currently supported.")
        # Keep button disabled and OFF state
        self.config_json["cus_protect"] = 0
        self.ui.Protection_switch_Button_8.setText("Disabled")
        self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_off"])
        # self.ui.Protection_switch_Button_8.setEnabled(False) # Optionally disable click
        self.init_config_write(self.config_json) # Save state if changed

    def change_sensitive(self): # Initialize/Toggle High Sensitivity
        if self.ui.high_sensitivity_switch_Button.text() == "Enabled":
            # Turn OFF
            self.config_json["sensitivity"] = 0
            self.ui.high_sensitivity_switch_Button.setText("Disabled")
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_off"])
        elif self.first_startup or self.question_event("This option may increase false positives. Are you sure you want to enable it?"):
            # Turn ON (after confirmation if not first startup)
            self.config_json["sensitivity"] = 1
            self.ui.high_sensitivity_switch_Button.setText("Enabled")
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_on"])
        # else: User cancelled the question, do nothing
        self.init_config_write(self.config_json)

    def extension_kit(self): # Initialize/Toggle Extended Scan Engine (YARA rules)
        if self.ui.extension_kit_switch_Button.text() == "Enabled":
             # Turn OFF
            self.config_json["extend_mode"] = 0
            self.ui.extension_kit_switch_Button.setText("Disabled")
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_off"])
        else:
             # Turn ON
            self.config_json["extend_mode"] = 1
            self.ui.extension_kit_switch_Button.setText("Enabled")
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_on"])
        self.init_config_write(self.config_json)

    def cloud_services(self): # Initialize/Toggle Cloud Scan Service (Marked as unsupported)
        self.info_event("This feature is not currently supported.")
        # Keep button disabled and OFF state
        self.config_json["service_url"] = "None" # Ensure config reflects disabled state
        self.ui.cloud_services_switch_Button.setText("Disabled")
        self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_off"])
        # self.ui.cloud_services_switch_Button.setEnabled(False) # Optionally disable click
        self.init_config_write(self.config_json) # Save state if changed


    def gc_collect_init(self): # Initialize periodic garbage collection
        try:
            self.gc_collect = 1
            Thread(target=self.gc_collect_thread, daemon=True).start()
        except Exception as e:
            print(e)

    def gc_collect_thread(self): # Garbage collection thread
        while self.gc_collect:
            try:
                # Run garbage collection periodically (e.g., every 5 seconds)
                # Running it too frequently (like 0.2s) might not be efficient
                time.sleep(5)
                collected = gc.collect()
                # Optional: print(f"GC collected {collected} objects")
            except Exception as e:
                print(f"Error in GC thread: {e}")
                # If error occurs, maybe wait longer before retrying
                time.sleep(30)


    def block_window_init(self): # Initialize popup window blocking
        try:
            # Only start the thread if there are actually items in the block list
            if self.config_json.get("block_lists") and isinstance(self.config_json["block_lists"], list) and len(self.config_json["block_lists"]) > 0:
                 self.block_window = 1
                 Thread(target=self.block_software_window, daemon=True).start()
            else:
                 self.block_window = 0 # Ensure flag is off if list is empty/invalid
        except Exception as e:
            print(f"Error initializing window blocking: {e}")

    def add_white_list(self): # Add folder/file to whitelist
        try:
            # Offer both file and directory selection
            dialog = QFileDialog(self, "Add Item to Whitelist")
            dialog.setFileMode(QFileDialog.ExistingFiles) # Allow selecting files or directories
            if dialog.exec_():
                selected_items = dialog.selectedFiles()
                added_count = 0
                if selected_items:
                    items_to_add = [item.replace("\\", "/") for item in selected_items]
                    if self.question_event(f"Add the following {len(items_to_add)} item(s) to the whitelist?\n" + "\n".join(items_to_add)):
                        # Ensure 'white_lists' exists and is a list
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


    def remove_white_list(self): # Remove folder/file from whitelist
         try:
            # Provide a way to select from the existing list or browse
            # For simplicity, let's use browse first
            dialog = QFileDialog(self, "Remove Item from Whitelist")
            dialog.setFileMode(QFileDialog.ExistingFiles)
            if dialog.exec_():
                selected_items = dialog.selectedFiles()
                removed_count = 0
                if selected_items:
                    items_to_remove = [item.replace("\\", "/") for item in selected_items]

                    # Check which selected items are actually in the list
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
                                     pass # Item already removed or wasn't there

                             if removed_count > 0:
                                 self.config_json["white_lists"] = current_whitelist # Update the list in config
                                 self.info_event(f"Successfully removed {removed_count} item(s) from the whitelist.")
                                 self.init_config_write(self.config_json)
                             # No message needed if nothing was removed after confirmation (shouldn't happen with check)
         except Exception as e:
             print(f"Error removing from whitelist: {e}")

    def add_software_window(self): # Add window definition to block list
        try:
            self.block_window = 0 # Temporarily pause blocking thread if running
            if self.question_event("Please click on the window you want to block after closing this message."):
                # Allow some time for user to switch focus
                time.sleep(0.5)
                # Loop until a suitable window is focused
                while True:
                    QApplication.processEvents() # Keep UI responsive
                    hWnd = self.user32.GetForegroundWindow()
                    if not hWnd: # No foreground window
                        time.sleep(0.1)
                        continue

                    window_info = self.get_window_info(hWnd)

                    # Check if it's a window we should ignore (like taskbar, desktop, self)
                    is_ignored = False
                    if not any(window_info.values()) : # Ignore if title and class are empty
                         is_ignored = True
                    else:
                         for ignored in self.pass_windows:
                             # Check if the current window matches any ignore pattern
                             # This needs careful matching (exact, partial, class only?)
                             # Simple exact match for now:
                             if window_info == ignored:
                                 is_ignored = True
                                 break
                             # Maybe check class name only for some?
                             # if list(window_info.values())[0] == list(ignored.values())[0] and list(ignored.keys())[0] == '':
                             #    is_ignored = True
                             #    break

                    if not is_ignored:
                         title = list(window_info.keys())[0]
                         class_name = list(window_info.values())[0]
                         confirm_text = f"Block this window?\nTitle: '{title}'\nClass: '{class_name}'"
                         if self.question_event(confirm_text):
                             # Ensure block_lists exists and is a list
                             if not isinstance(self.config_json.get("block_lists"), list):
                                 self.config_json["block_lists"] = []

                             if window_info not in self.config_json["block_lists"]:
                                 self.config_json["block_lists"].append(window_info)
                                 self.info_event(f"Added to block list: {window_info}")
                                 self.init_config_write(self.config_json)
                             else:
                                 self.info_event(f"Window already in block list: {window_info}")
                         # else: User cancelled blocking this window
                         break # Exit loop after finding a suitable window and asking user
                    else:
                         # Optional: Notify user they clicked an ignored window?
                         # print("Ignoring this window...")
                         pass

                    time.sleep(0.1) # Small delay before checking again
            # else: User cancelled the initial instruction message

            self.block_window_init() # Restart blocking thread if necessary
        except Exception as e:
            print(f"Error adding window to block: {e}")
            self.block_window_init() # Ensure thread restarts on error

    def remove_software_window(self): # Remove window definition from block list
        try:
            self.block_window = 0 # Temporarily pause blocking thread
            if self.question_event("Please click on the window you want to remove from the block list after closing this message."):
                time.sleep(0.5)
                while True:
                    QApplication.processEvents()
                    hWnd = self.user32.GetForegroundWindow()
                    if not hWnd:
                         time.sleep(0.1)
                         continue

                    window_info = self.get_window_info(hWnd)

                    # Check if this window definition is actually in our block list
                    current_block_list = self.config_json.get("block_lists", [])
                    is_in_list = window_info in current_block_list

                    # Similar ignore check as in add_software_window might be useful here too
                    # to prevent accidentally trying to unblock the taskbar etc.
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
                             # else: User cancelled removal
                             break # Exit loop after finding a window and asking user
                        else:
                             # Notify user the window isn't blocked
                             info_text = f"This window is not currently in the block list.\nTitle: '{title}'\nClass: '{class_name}'"
                             self.info_event(info_text)
                             # Should we break here or let them try another window? Let's break for simplicity.
                             break

                    time.sleep(0.1)
            # else: User cancelled the initial instruction message

            self.block_window_init() # Restart blocking thread if necessary
        except Exception as e:
            print(f"Error removing window from block list: {e}")
            self.block_window_init() # Ensure thread restarts on error


    def get_window_info(self, hWnd): # Get window title and class name
        try:
            length = self.user32.GetWindowTextLengthW(hWnd)
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            self.user32.GetWindowTextW(hWnd, title_buffer, length + 1)
            window_title = title_buffer.value

            class_buffer = ctypes.create_unicode_buffer(256) # Class names are usually shorter
            self.user32.GetClassNameW(hWnd, class_buffer, 256)
            class_name = class_buffer.value

            return {window_title: class_name}
        except Exception as e:
             print(f"Error getting window info for HWND {hWnd}: {e}")
             return {'': ''} # Return empty info on error


    def enum_windows_callback(self, hWnd, lParam): # Callback for EnumWindows
        # Append HWND to the list stored in lParam (passed via EnumWindows)
        # We need to cast lParam back to a Python object reference if we pass one
        # Simpler approach: use a class member list directly if possible.
        # Let's stick to the original approach using a member list:
        self.hwnd_list.append(hWnd)
        return True # Continue enumeration

    def get_all_windows(self): # Get handles of all top-level windows
        self.hwnd_list = [] # Reset the list
        # Define the callback function type
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        # Create a callable instance of the callback function type
        enum_proc = WNDENUMPROC(self.enum_windows_callback)
        # Call EnumWindows, passing 0 for lParam as we're using a member variable
        self.user32.EnumWindows(enum_proc, 0)
        return self.hwnd_list

    def block_software_window(self):  # Window blocking thread
        print("Window blocking thread started.")
        while self.block_window:
            try:
                time.sleep(0.2) # Check frequency
                current_block_list = self.config_json.get("block_lists", [])
                if not current_block_list: # No need to check if list is empty
                    # Stop the thread if list becomes empty? Or just sleep longer?
                    # Let's keep it running but sleep longer if list is empty.
                    time.sleep(2)
                    continue

                # Get all windows *once* per loop iteration for efficiency
                all_hwnds = self.get_all_windows()

                for hWnd in all_hwnds:
                    # Check if window is still valid before getting info
                    if not self.user32.IsWindow(hWnd):
                        continue

                    window_info = self.get_window_info(hWnd)

                    # Check if this window matches any definition in the block list
                    if window_info in current_block_list:
                        print(f"Blocking window: {window_info}")
                        # Try closing the window gracefully first
                        self.user32.PostMessageW(hWnd, 0x0010, 0, 0) # WM_CLOSE
                        # Optional: Add a small delay to see if it closes
                        time.sleep(0.05)
                        # If still exists, force close (might be less graceful)
                        if self.user32.IsWindow(hWnd):
                             print(f"Force closing window: {window_info}")
                             # WM_SYSCOMMAND with SC_CLOSE is often effective
                             self.user32.PostMessageW(hWnd, 0x0112, 0xF060, 0) # WM_SYSCOMMAND, SC_CLOSE
                             # Other messages might be redundant or less effective
                             # self.user32.SendMessageW(hWnd, 0x0002, 0, 0) # WM_DESTROY (use with caution)
                             # self.user32.SendMessageW(hWnd, 0x0012, 0, 0) # WM_QUIT (usually for thread message loop)
                        # Add a small pause after attempting to close to avoid high CPU
                        time.sleep(0.1)

            except Exception as e:
                print(f"Error in window blocking thread: {e}")
                # Wait before retrying after an error
                time.sleep(5)
        print("Window blocking thread stopped.")


    def init_config_show(self): # Show window with fade-in effect
        def update_opacity():
            current_opacity = self.windowOpacity()
            if current_opacity < 1.0:
                 new_opacity = min(current_opacity + 0.02, 1.0) # Increase by 2%
                 self.setWindowOpacity(new_opacity)
            else:
                 self.opacity_timer.stop() # Stop timer when fully opaque

        # Reset opacity before showing if it was hidden
        self.setWindowOpacity(0.0)
        self.show()

        # Use a QTimer for smooth animation
        self.opacity_timer = QTimer(self)
        self.opacity_timer.timeout.connect(update_opacity)
        self.opacity_timer.start(10) # Update every 10ms for smoother effect


    def init_config_hide(self): # Hide window with fade-out effect
        def update_opacity():
            current_opacity = self.windowOpacity()
            if current_opacity > 0.0:
                 new_opacity = max(current_opacity - 0.02, 0.0) # Decrease by 2%
                 self.setWindowOpacity(new_opacity)
            else:
                 self.opacity_timer.stop() # Stop timer when fully transparent
                 self.hide() # Hide the window completely

        # Start fade-out only if window is currently visible
        if self.isVisible():
            self.opacity_timer = QTimer(self)
            self.opacity_timer.timeout.connect(update_opacity)
            self.opacity_timer.start(10) # Update every 10ms


    def showMinimized(self): # Minimize window (optionally hide to tray)
        # Decide whether to just minimize or hide to tray
        # Let's assume default minimize behavior unless explicitly configured otherwise
        # For hiding to tray:
        # self.init_config_hide() # Fade out and hide
        # self.send_notify("PYAS minimized to system tray.", notify_bar=True) # Show tray message

        # Standard minimize:
        self.showMinimized()


    def nativeEvent(self, eventType, message):
        # Intercept system messages like close attempts if needed
        try:
             # Check if message is a valid pointer
             if message:
                 msg = ctypes.wintypes.MSG.from_address(int(message))
                 # Intercept standard close messages (WM_CLOSE, WM_SYSCOMMAND+SC_CLOSE)
                 # WM_DESTROY (0x0002), WM_QUIT (0x0012) are less common for direct user close action
                 if msg.message == 0x0010: # WM_CLOSE
                     # print("Native WM_CLOSE intercepted")
                     # self.close() # Trigger our custom close logic
                     # return True, 0 # Indicate we handled it
                     pass # Let closeEvent handle it for consistency
                 elif msg.message == 0x0112 and (msg.wParam & 0xFFF0) == 0xF060: # WM_SYSCOMMAND, SC_CLOSE
                     # print("Native SC_CLOSE intercepted")
                     # self.close() # Trigger our custom close logic
                     # return True, 0 # Indicate we handled it
                     pass # Let closeEvent handle it

        except Exception as e:
             print(f"Error in nativeEvent: {e}")

        # Call base class implementation for unhandled events
        return super(MainWindow_Controller, self).nativeEvent(eventType, message)


    def closeEvent(self, event): # Handle window close event (X button, Alt+F4)
        # Ask for confirmation before closing
        if self.question_event("Are you sure you want to exit PYAS and stop all protections?"):
            print("Exiting application...")
            # --- Cleanup actions ---
            self.init_config_write(self.config_json) # Save current settings
            self.clean_function() # Stop threads, potentially stop driver
            print("Cleanup complete. Accepting close event.")
            event.accept() # Allow the window to close
            QApplication.quit() # Ensure the application exits cleanly
        else:
            print("Close event ignored by user.")
            event.ignore() # Prevent the window from closing


    def show_menu(self): # Show "About" window (previously menu)
        # Simplified: Just show the About widget directly
        if self.ui.About_widget.isHidden():
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.Setting_widget.hide()
            self.ui.About_widget.show()
            self.Process_Timer.stop() # Stop process list timer if running
            # Apply animations
            self.change_animation_3(self.ui.About_widget, 0.5) # Fade-in effect
            self.change_animation_5(self.ui.About_widget, 80, 50, 761, 481) # Positional animation


    def update_database(self): # Update signatures/rules (Placeholder)
        try:
            if self.question_event("Are you sure you want to check for updates?"):
                self.info_event("Update check feature is not implemented yet.")
                # Placeholder for future update logic:
                # 1. Check version/database timestamp from a server (config_json["service_url"]?)
                # 2. Compare with local version/timestamp.
                # 3. If update available, download new rules/models.
                # 4. Replace old files (handle permissions, backups).
                # 5. Reload engines (self.init_config_data()).
                pass
        except Exception as e:
            print(f"Error during update check: {e}")

    # --- Animation Functions ---

    def change_animation(self, widget): # Slide-in animation from left
        """Animates widget sliding in from the left."""
        target_x = 80 # Target X position
        start_x = target_x - 60 # Starting X position (off-screen left)
        y = widget.pos().y() # Keep current Y position
        width, height = 761, 481 # Target dimensions

        widget.setGeometry(QRect(start_x, y, width, height)) # Set initial position

        self.anim = QPropertyAnimation(widget, b"geometry")
        self.anim.setDuration(300) # Animation duration in ms
        self.anim.setStartValue(QRect(start_x, y, width, height))

        # Use easing curve for smoother motion
        self.anim.setEasingCurve(QEasingCurve.OutCubic)

        # Intermediate steps (optional, QEasingCurve often handles this better)
        # self.anim.setKeyValueAt(0.2, QRect(target_x - 30, y, width, height))
        # self.anim.setKeyValueAt(0.4, QRect(target_x - 10, y, width, height))

        self.anim.setEndValue(QRect(target_x, y, width, height)) # Final position
        self.anim.start(QAbstractAnimation.DeleteWhenStopped) # Auto-delete animation


    def change_animation_3(self, widget, duration_sec): # Fade-in animation
        """Animates widget fading in."""
        self.opacity_effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(self.opacity_effect)
        # widget.setAutoFillBackground(True) # Might not be necessary depending on styling

        self.anim_opacity = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim_opacity.setDuration(int(duration_sec * 1000)) # Duration in ms
        self.anim_opacity.setStartValue(0.0) # Start fully transparent
        self.anim_opacity.setEndValue(1.0)   # End fully opaque
        self.anim_opacity.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_opacity.start(QAbstractAnimation.DeleteWhenStopped)


    # Removed timeout method as change_animation_3 uses QPropertyAnimation now


    def change_animation_4(self, widget, duration_ms, start_height, end_height): # Vertical expand/collapse animation
        """Animates widget height change."""
        x = widget.pos().x()
        y = widget.pos().y() # Assuming Y position doesn't change
        width = widget.width() # Keep current width

        self.anim_height = QPropertyAnimation(widget, b"geometry")
        self.anim_height.setDuration(duration_ms)
        self.anim_height.setStartValue(QRect(x, y, width, start_height))
        self.anim_height.setEndValue(QRect(x, y, width, end_height))
        self.anim_height.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_height.start(QAbstractAnimation.DeleteWhenStopped)


    def change_animation_5(self, widget, target_x, target_y, target_width, target_height): # Drop-down animation
        """Animates widget dropping down from above."""
        start_y = target_y - 45 # Starting Y position (above target)

        widget.setGeometry(QRect(target_x, start_y, target_width, target_height)) # Set initial position

        self.anim_drop = QPropertyAnimation(widget, b"geometry")
        self.anim_drop.setDuration(350) # Duration in ms
        self.anim_drop.setStartValue(QRect(target_x, start_y, target_width, target_height))

        # Use easing curve for bounce effect (optional) or smooth drop
        self.anim_drop.setEasingCurve(QEasingCurve.OutBounce) # Example bounce
        # self.anim_drop.setEasingCurve(QEasingCurve.OutCubic) # Example smooth drop

        self.anim_drop.setEndValue(QRect(target_x, target_y, target_width, target_height)) # Final position
        self.anim_drop.start(QAbstractAnimation.DeleteWhenStopped)


    # --- Widget Switching Functions ---

    def _switch_main_widget(self, widget_to_show):
        """Helper function to hide all main widgets and show the specified one with animation."""
        widgets = [
            self.ui.State_widget,
            self.ui.Virus_Scan_widget,
            self.ui.Tools_widget,
            self.ui.Protection_widget,
            self.ui.Process_widget, # Treat Process as a main widget too
            self.ui.Setting_widget,
            self.ui.About_widget
        ]

        for widget in widgets:
             if widget.isVisible() and widget != widget_to_show:
                 widget.hide() # Hide others immediately

        if widget_to_show.isHidden():
             # Stop process timer if switching away from Process widget
             if widget_to_show != self.ui.Process_widget:
                 self.Process_Timer.stop()

             # Show and animate the target widget
             widget_to_show.show()
             self.change_animation_3(widget_to_show, 0.3) # Quick fade-in
             self.change_animation(widget_to_show)     # Slide-in

             # Special handling for Process widget timer
             if widget_to_show == self.ui.Process_widget:
                  self.process_list() # Initial population
                  self.Process_Timer.start(1000) # Update every 1 second


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

    def change_tools(self, widget): # Handles switching *from* Tools page to a specific tool (like Process Manager)
        # This seems redundant if Process Manager is treated as a main page.
        # If Tools page has sub-widgets, this logic is needed.
        # Assuming Process Manager is now a main page, this function might be simplified or removed.
        # Let's adapt it assuming Process Manager (self.ui.Process_widget) is the only target from Tools.
        if widget == self.ui.Process_widget:
            self._switch_main_widget(self.ui.Process_widget)
        # else: handle other tools if they exist


    # --- Mouse Dragging and Window Styling ---

    def mousePressEvent(self, event): # Handle mouse press for dragging
        # Check if the press is on the title bar area (adjust coordinates as needed)
        title_bar_rect = QRect(10, 10, self.width() - 20, 40) # Example rect for title bar
        if event.button() == Qt.LeftButton and title_bar_rect.contains(event.pos()):
            self.m_flag = True # Flag to indicate dragging started
            # Calculate offset from window top-left to mouse click position
            self.m_Position = event.globalPos() - self.pos()
            event.accept()
            # Optional: Change cursor? self.setCursor(Qt.OpenHandCursor)
            # Optional: Slight opacity decrease effect while dragging
            # self.start_drag_opacity_effect(True)


    def mouseMoveEvent(self, event): # Handle mouse move for dragging
        if self.m_flag and event.buttons() == Qt.LeftButton: # Check flag and button held
            # Calculate new window position
            new_pos = event.globalPos() - self.m_Position
            self.move(new_pos)
            event.accept()


    def mouseReleaseEvent(self, event): # Handle mouse release after dragging
        if event.button() == Qt.LeftButton:
            self.m_flag = False # Stop dragging
            # Optional: Restore cursor? self.setCursor(Qt.ArrowCursor)
            # Optional: Restore full opacity
            # self.start_drag_opacity_effect(False)


    # Optional helper for drag opacity effect
    # def start_drag_opacity_effect(self, drag_start):
    #     target_opacity = 0.85 if drag_start else 1.0
    #     self.drag_opacity_anim = QPropertyAnimation(self, b"windowOpacity")
    #     self.drag_opacity_anim.setDuration(150)
    #     self.drag_opacity_anim.setEndValue(target_opacity)
    #     self.drag_opacity_anim.start(QAbstractAnimation.DeleteWhenStopped)


    def paintEvent(self, event): # Custom painting for rounded corners/borders
        # This is for creating the main window shape with rounded corners using QPainter
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing) # Smooth edges
        painter.setBrush(Qt.transparent) # Use transparent brush initially

        # Define the outer path (slightly larger than the area to be drawn)
        outer_rect = self.rect()
        # Define the inner path (the actual visible area)
        inner_rect = QRect(10, 10, outer_rect.width() - 20, outer_rect.height() - 20)

        # Use a path to clip the drawing area (optional, depends on desired effect)
        # path = QPainterPath()
        # path.addRoundedRect(inner_rect, 5, 5) # Adjust radius as needed
        # painter.setClipPath(path)

        # Draw the rounded background (using the theme's window style color if possible)
        # Note: setStyleSheet often handles background, this might conflict or be redundant.
        # If using stylesheet for background, this paintEvent might only be for border/shape.
        # Let's assume stylesheet handles background and this is just for shape/border.

        # Draw a rounded rectangle border (example)
        painter.setPen(QPen(Qt.gray, 1)) # Example: 1px gray border
        painter.setBrush(Qt.transparent) # No fill, just border
        painter.drawRoundedRect(inner_rect, 5, 5) # Adjust radius

        super().paintEvent(event) # Call base class paintEvent


    # --- Event/Notification Helpers ---

    def info_event(self, text): # Show informational message box
        try:
            print(f"[Info] > {text}")
            # Only show message box if not during initial startup
            if not self.first_startup:
                QMessageBox.information(self, "Information", str(text), QMessageBox.Ok)
        except Exception as e:
            print(f"Error showing info event: {e}")


    def question_event(self, text): # Show question message box and return True/False
        try:
            print(f"[Quest] > {text}")
            # Always show question box, even during startup if needed (e.g., critical choices)
            # if not self.first_startup:
            reply = QMessageBox.question(self, "Confirmation", str(text),
                                          QMessageBox.Yes | QMessageBox.No, QMessageBox.No) # Default No
            return reply == QMessageBox.Yes
            # return False # Default to False if during startup and questions should be skipped?
        except Exception as e:
            print(f"Error showing question event: {e}")
            return False # Default to False on error


    def send_notify(self, text, notify_bar=True): # Send notification to log and tray
        try:
            now_time = time.strftime('%Y-%m-%d %H:%M:%S')
            log_message = f"[{now_time}] {text}"
            print(f"[Notify] > {log_message}")

            # Append to the status log widget safely using invokeMethod for cross-thread calls
            QMetaObject.invokeMethod(self.ui.State_output, "append",
                                     Qt.QueuedConnection, Q_ARG(str, log_message))

            # Show tray notification if requested and not during startup
            if notify_bar and not self.first_startup and self.tray_icon.isVisible():
                self.tray_icon.showMessage("Foxy Security Notification", text,
                                           QSystemTrayIcon.Information, 5000) # Use enum, add duration
        except Exception as e:
            print(f"Error sending notification: {e}")


    # --- Process List Management ---

    def process_list(self): # Update process list UI
        try:
            current_pids = self.get_process_list()
            if current_pids is None: return # Error getting PIDs

            # Check if the number of processes has changed significantly to trigger full update
            # Or update periodically regardless? Let's update if changed.
            if current_pids != self.exist_process: # Compare sets for changes
                Process_list_app_data = []
                for pid in sorted(list(current_pids)): # Sort PIDs numerically
                    QApplication.processEvents() # Keep UI responsive during list build
                    h_process = self.kernel32.OpenProcess(0x1000 | 0x0400, False, pid) # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                    if h_process:
                        file = self.get_process_file(h_process) # Get path
                        self.kernel32.CloseHandle(h_process)
                        if file: # Check if path retrieval was successful
                            # Use PID for sorting, display string for UI
                            Process_list_app_data.append((pid, f"[{pid}] > {file.replace('\\', '/')}"))
                        # else: Handle case where path couldn't be retrieved? Maybe skip.
                    # else: Handle case where process couldn't be opened (permissions?)

                # Update internal list of PIDs (sorted by PID from Process_list_app_data)
                self.Process_list_all_pid = [p[0] for p in Process_list_app_data]

                # Update UI
                if len(self.Process_list_all_pid) != self.Process_quantity:
                    self.Process_quantity = len(self.Process_list_all_pid)
                    self.ui.Process_Total_View.setText(str(self.Process_quantity))

                process_display_list = [p[1] for p in Process_list_app_data]
                self.Process_sim.setStringList(process_display_list)
                self.ui.Process_list.setModel(self.Process_sim)

                # Update the reference set for the next check
                self.exist_process = current_pids

        except Exception as e:
            print(f"Error updating process list: {e}")


    def process_list_menu(self, pos): # Context menu for process list
        try:
            selected_indexes = self.ui.Process_list.selectedIndexes()
            if not selected_indexes: return # No item selected

            # Assuming single selection mode
            selected_row = selected_indexes[0].row()
            if selected_row < len(self.Process_list_all_pid):
                selected_pid = self.Process_list_all_pid[selected_row]
                selected_text = self.Process_sim.stringList()[selected_row] # Get the text for display/confirmation

                # Get process path for confirmation message
                hProcessCheck = self.kernel32.OpenProcess(0x1000, False, selected_pid) # Query info permission
                file_path_check = ""
                if hProcessCheck:
                     file_path_check = self.get_process_file(hProcessCheck).replace('\\', '/')
                     self.kernel32.CloseHandle(hProcessCheck)

                # Create context menu
                self.Process_popMenu = QMenu(self)
                kill_Process_Action = QAction(f"End Process ({selected_pid})", self) # Show PID in action
                copy_Path_Action = QAction("Copy Path", self)
                # Add more actions: Properties, Open File Location, etc.

                self.Process_popMenu.addAction(kill_Process_Action)
                if file_path_check: # Only add copy path if path is valid
                     self.Process_popMenu.addAction(copy_Path_Action)

                # Execute menu and handle selected action
                action = self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos))

                if action == kill_Process_Action:
                    # Confirmation before killing
                    confirm_msg = f"Are you sure you want to terminate process:\n{selected_text}?"
                    if self.question_event(confirm_msg):
                        try:
                            # Open process with Terminate permission
                            hProcessKill = self.kernel32.OpenProcess(0x0001, False, selected_pid) # PROCESS_TERMINATE
                            if hProcessKill:
                                if file_path_check == self.path_pyas:
                                     self.info_event("Cannot terminate the application itself this way. Use the close button.")
                                     self.kernel32.CloseHandle(hProcessKill)
                                     # self.close() # Optionally trigger self-close?
                                else:
                                     # Terminate the process
                                     success = self.kernel32.TerminateProcess(hProcessKill, 1) # Exit code 1
                                     self.kernel32.CloseHandle(hProcessKill)
                                     if success:
                                         self.info_event(f"Process {selected_pid} terminated.")
                                         # Refresh the list immediately
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


    # --- Virus Scan Logic ---

    def init_scan(self): # Initialize UI and variables for a new scan
        try:
            self.ui.Virus_Scan_text.setText("Initializing...")
            QApplication.processEvents() # Update UI text

            # Release any previous file locks
            try:
                # Create a copy of keys to iterate over as dictionary size might change
                locked_files = list(self.virus_lock.keys())
                for file in locked_files:
                    self.lock_file(file, False) # Unlock and close
            except Exception as unlock_err:
                print(f"Warning: Error unlocking previous files: {unlock_err}")
                self.virus_lock = {} # Reset lock dict just in case

            # Reset scan state variables
            self.scan_file = True # Flag to control scan loop
            self.total_scan = 0
            self.scan_time = time.time()
            self.virus_lock = {} # Dictionary to hold locked file handles {filepath: handle}
            self.virus_list_ui = [] # List to store display strings of found viruses

            # Update UI elements for scanning state
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.Virus_Scan_choose_widget.hide() # Hide scan type choice during scan
            self.ui.Virus_Scan_choose_Button.hide()
            self.ui.Virus_Scan_Break_Button.show()
            self.ui.Virus_Scan_output.clear() # Clear previous results

            # Change titles to indicate scanning
            self.ui.Virus_Scan_title.setText("Scanning")

        except Exception as e:
            print(f"Error initializing scan: {e}")


    def Virus_Scan_output_menu(self, point): # Context menu for scan results list
        selected_items = self.ui.Virus_Scan_output.selectedItems()
        if not selected_items: return

        item = selected_items[0] # Assuming single selection
        item_text = item.text()

        # Extract file path from item text (assuming format "[State] FilePath")
        file_path = ""
        if "]" in item_text:
             try:
                 file_path = item_text.split("] ", 1)[1]
             except IndexError:
                 pass # Couldn't parse path

        menu = QMenu(self)
        copyPathAction = menu.addAction("Copy Path")
        openLocationAction = menu.addAction("Open File Location")
        # Add more actions: Add to Whitelist, Scan Again?

        # Disable actions if path is invalid
        copyPathAction.setEnabled(bool(file_path))
        openLocationAction.setEnabled(bool(file_path) and os.path.exists(os.path.dirname(file_path)))

        action = menu.exec_(self.ui.Virus_Scan_output.mapToGlobal(point))

        if action == copyPathAction and file_path:
            pyperclip.copy(file_path.replace("/", "\\")) # Copy with backslashes for Windows
            self.info_event("Path copied to clipboard.")
        elif action == openLocationAction and file_path:
            try:
                 dir_path = os.path.dirname(file_path).replace("/", "\\")
                 # Use explorer to open the directory and select the file
                 subprocess.run(['explorer', '/select,', dir_path + "\\" + os.path.basename(file_path)], check=True)
            except Exception as open_err:
                 self.info_event(f"Could not open file location: {open_err}")


    def lock_file(self, file_path, lock): # Lock/Unlock a file using msvcrt
        """Locks or unlocks a file using msvcrt locking."""
        try:
            if lock:
                # Check if already locked by us
                if file_path not in self.virus_lock:
                    # Need Read/Write access to lock usually
                    handle = os.open(file_path, os.O_RDWR | os.O_BINARY)
                    file_size = os.path.getsize(file_path)
                    # Lock the entire file (non-blocking)
                    msvcrt.locking(handle, msvcrt.LK_NBLCK, file_size if file_size > 0 else 1) # Lock 1 byte if empty
                    self.virus_lock[file_path] = handle # Store handle
                    print(f"Locked: {file_path}")
            else:
                # Unlock if we have the handle
                if file_path in self.virus_lock:
                    handle = self.virus_lock[file_path]
                    file_size = os.path.getsize(file_path) # Get size again, might have changed
                    # Unlock the file
                    msvcrt.locking(handle, msvcrt.LK_UNLCK, file_size if file_size > 0 else 1)
                    os.close(handle) # Close the handle
                    del self.virus_lock[file_path] # Remove from dict
                    print(f"Unlocked: {file_path}")

        except OSError as e:
             # Common errors: Permission denied, File not found, File is locked by another process
             print(f"OS Error locking/unlocking {file_path}: {e}")
             # If locking failed, ensure it's not in our dict
             if lock and file_path in self.virus_lock:
                  del self.virus_lock[file_path]
             # If unlocking failed, maybe the handle was already closed or invalid
             if not lock and file_path in self.virus_lock:
                  # Try closing just in case, ignore errors
                  try: os.close(self.virus_lock[file_path])
                  except: pass
                  del self.virus_lock[file_path]
        except Exception as e:
             print(f"General Error locking/unlocking file {file_path}: {e}")


    def virus_solve(self): # Delete selected viruses from the scan results
        try:
            items_to_delete = []
            items_to_keep = [] # Keep track of items not selected for deletion

            # Iterate through all items in the list widget
            for i in range(self.ui.Virus_Scan_output.count()):
                item = self.ui.Virus_Scan_output.item(i)
                item_text = item.text()
                file_path = ""
                if "]" in item_text:
                     try: file_path = item_text.split("] ", 1)[1]
                     except IndexError: pass

                if file_path: # Proceed only if path is valid
                    if item.checkState() == Qt.Checked:
                        items_to_delete.append((item, file_path))
                    else:
                        items_to_keep.append((item, file_path))

            if not items_to_delete:
                self.info_event("No items selected for deletion.")
                return

            if not self.question_event(f"Are you sure you want to delete {len(items_to_delete)} selected item(s)? This action cannot be undone."):
                return # User cancelled

            # --- Start Deletion ---
            self.ui.Virus_Scan_Solve_Button.setEnabled(False) # Disable button during deletion
            self.ui.Virus_Scan_title.setText("Deleting Files...")
            QApplication.processEvents()

            deleted_count = 0
            failed_files = []

            for item, file_path in items_to_delete:
                 try:
                    # Update status text
                    self.ui.Virus_Scan_text.setText(f"Deleting: {os.path.basename(file_path)}")
                    QApplication.processEvents()

                    # Ensure file is unlocked before attempting deletion
                    self.lock_file(file_path, False)

                    # Attempt deletion
                    if os.path.exists(file_path):
                         # Use robust deletion method if needed (e.g., send2trash)
                         os.remove(file_path)
                         deleted_count += 1
                         # Remove item from the UI list widget immediately after successful deletion
                         # self.ui.Virus_Scan_output.takeItem(self.ui.Virus_Scan_output.row(item))
                         print(f"Deleted: {file_path}")
                    else:
                         print(f"File not found (already deleted?): {file_path}")
                         # Consider removing item from list even if not found?

                 except Exception as delete_err:
                     print(f"Failed to delete {file_path}: {delete_err}")
                     failed_files.append(os.path.basename(file_path))
                     # Keep the item in the list if deletion failed

            # --- Post Deletion ---
            # Refresh the list view to show only remaining items (or clear if all deleted)
            self.ui.Virus_Scan_output.clear()
            self.virus_list_ui = [] # Reset internal list
            for item, file_path in items_to_keep:
                 # Re-add items that were not deleted
                 list_item = QListWidgetItem(item.text()) # Create new item
                 list_item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                 list_item.setCheckState(Qt.Unchecked) # Default to unchecked after solve
                 self.ui.Virus_Scan_output.addItem(list_item)
                 self.virus_list_ui.append(item.text()) # Rebuild internal list

            # Update titles and buttons based on remaining items
            if failed_files or items_to_keep:
                 self.ui.Virus_Scan_title.setText("Deletion Complete (Failures Occurred)")
                 self.ui.Virus_Scan_text.setText(f"Deleted {deleted_count} items. Failed: {len(failed_files)}. Remaining: {len(items_to_keep)}.")
                 self.ui.Virus_Scan_Solve_Button.show() # Show solve button again
                 self.ui.Virus_Scan_Solve_Button.setEnabled(True)
                 self.info_event(f"Deletion finished. Failed to delete: {', '.join(failed_files)}")
            else:
                 self.ui.Virus_Scan_title.setText("Deletion Complete")
                 self.ui.Virus_Scan_text.setText(f"Successfully deleted {deleted_count} items.")
                 self.ui.Virus_Scan_Solve_Button.hide() # Hide solve button if list is empty
                 self.ui.Virus_Scan_Break_Button.hide() # Scan finished
                 self.ui.Virus_Scan_choose_Button.show() # Show scan choice button

        except Exception as e:
            print(f"Error during virus solve process: {e}")
            self.ui.Virus_Scan_title.setText("Error During Deletion")
            self.ui.Virus_Scan_text.setText("An unexpected error occurred.")
            self.ui.Virus_Scan_Solve_Button.setEnabled(True) # Re-enable button on error


    def write_scan(self, state, file_path): # Add scan result to the UI list
        """Adds a formatted scan result to the Virus Scan output list."""
        try:
            if state and file_path:
                 display_text = f"[{state}] {file_path}"
                 # Lock the file immediately upon detection
                 self.lock_file(file_path, True)
                 # Add to internal list first
                 self.virus_list_ui.append(display_text)
                 # Create and add item to the QListWidget
                 item = QListWidgetItem(display_text)
                 item.setFlags(item.flags() | Qt.ItemIsUserCheckable) # Make it checkable
                 item.setCheckState(Qt.Checked) # Default to checked (selected for deletion)
                 # Use invokeMethod for thread safety when updating UI from scan thread
                 QMetaObject.invokeMethod(self.ui.Virus_Scan_output, "addItem", Qt.QueuedConnection, Q_ARG(QListWidgetItem, item))
        except Exception as e:
             print(f"Error writing scan result for {file_path}: {e}")


    def answer_scan(self): # Summarize scan results and update UI
        """Updates UI titles and buttons after a scan completes."""
        try:
            # Ensure UI updates happen on the main thread
            def update_ui():
                self.ui.Virus_Scan_title.setText("Virus Scan") # Reset title
                takes_time = int(time.time() - self.scan_time)
                if not self.virus_list_ui: # No viruses found
                     result_text = f"Scan complete. No threats found."
                     summary_text = f"Scanned {self.total_scan} files in {takes_time} seconds."
                     self.ui.Virus_Scan_Solve_Button.hide()
                     self.ui.Virus_Scan_Break_Button.hide()
                     self.ui.Virus_Scan_choose_Button.show()
                else: # Viruses found
                     found_count = len(self.virus_list_ui)
                     result_text = f"Scan complete. Found {found_count} threat(s)."
                     summary_text = f"Scanned {self.total_scan} files in {takes_time} seconds."
                     self.ui.Virus_Scan_Solve_Button.show()
                     self.ui.Virus_Scan_Break_Button.hide()
                     self.ui.Virus_Scan_choose_Button.show()

                final_text = f"{result_text} {summary_text}"
                self.ui.Virus_Scan_text.setText(final_text)
                self.send_notify(final_text, notify_bar=True) # Send tray notification

            # If called from a worker thread, use invokeMethod or QTimer.singleShot
            if QThread.currentThread() != self.thread():
                 QTimer.singleShot(0, update_ui)
            else:
                 update_ui()

        except Exception as e:
            print(f"Error summarizing scan results: {e}")
            # Attempt basic UI reset even on error
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText", Qt.QueuedConnection, Q_ARG(str, "Virus Scan"))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, "Scan finished with errors."))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_Break_Button, "hide")
            QMetaObject.invokeMethod(self.ui.Virus_Scan_choose_Button, "show")


    def virus_scan_break(self): # Stop the current scan
        print("Scan stop requested.")
        self.scan_file = False # Signal scan threads to stop
        # Update UI immediately
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()
        self.ui.Virus_Scan_title.setText("Scan Stopped")
        self.ui.Virus_Scan_text.setText("Scan stopped by user.")
        # Note: Doesn't call answer_scan, as it's an interruption, not completion.
        # Existing results remain in the list. User can choose to Solve or start new scan.
        # If results exist, show Solve button?
        if self.virus_list_ui:
             self.ui.Virus_Scan_Solve_Button.show()


    def virus_scan_menu(self): # Show/Hide the scan type selection widget
        widget = self.ui.Virus_Scan_choose_widget
        if widget.isHidden():
            widget.show()
            # Animate expanding vertically
            self.change_animation_4(widget, 150, 0, 101) # Duration, start height, end height
        else:
            # Animate collapsing vertically (reverse heights)
            self.change_animation_4(widget, 150, widget.height(), 0)
            # Use QTimer to hide after animation finishes
            QTimer.singleShot(160, widget.hide) # Hide slightly after animation duration


    def _run_scan_thread(self, target_func, *args):
        """Helper to run a scan function in a thread and handle completion."""
        try:
            self.init_scan() # Prepare UI for scanning

            # Create and start the scan thread
            self.scan_thread = Thread(target=target_func, args=args, daemon=True)
            self.scan_thread.start()

            # Use QTimer to periodically check if thread finished, keeping UI responsive
            self.scan_check_timer = QTimer(self)
            def check_scan_finish():
                if not self.scan_thread.is_alive():
                    self.scan_check_timer.stop()
                    # Ensure results are processed on main thread if needed
                    QTimer.singleShot(0, self.answer_scan) # Summarize results
                else:
                    # Keep UI responsive while scanning
                    QApplication.processEvents()

            self.scan_check_timer.timeout.connect(check_scan_finish)
            self.scan_check_timer.start(100) # Check every 100ms

        except Exception as e:
            print(f"Error starting scan thread for {target_func.__name__}: {e}")
            self.virus_scan_break() # Reset UI to safe state on error


    def file_scan(self): # Scan a single selected file
        try:
            options = QFileDialog.Options()
            # options |= QFileDialog.DontUseNativeDialog # Optional: use Qt dialog
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*);;Executable Files (*.exe *.dll *.sys)", options=options)

            if file_path:
                file_path = file_path.replace("\\", "/")
                if self.check_whitelist(file_path):
                    self.info_event(f"File is in whitelist, skipping scan: {file_path}")
                    return

                # Define the target function for the thread
                def scan_single_file(f_path):
                    scan_result = self.start_scan(f_path)
                    self.write_scan(scan_result, f_path) # Add result to list
                    self.total_scan += 1

                # Run the scan in a thread
                self._run_scan_thread(scan_single_file, file_path)

        except Exception as e:
            print(f"Error during file scan setup: {e}")
            self.virus_scan_break()


    def path_scan(self): # Scan a selected directory
        try:
            options = QFileDialog.Options()
            options |= QFileDialog.ShowDirsOnly
            # options |= QFileDialog.DontUseNativeDialog
            dir_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan", "", options=options)

            if dir_path:
                dir_path = dir_path.replace("\\", "/")
                if self.check_whitelist(dir_path):
                     self.info_event(f"Folder is within a whitelisted path, skipping scan: {dir_path}")
                     return

                # Run the traversal and scan in a thread
                self._run_scan_thread(self.traverse_path, dir_path)

        except Exception as e:
            print(f"Error during path scan setup: {e}")
            self.virus_scan_break()


    def disk_scan(self): # Scan all logical drives
        try:
            drives = [f"{chr(l)}:/" for l in range(65, 91) if os.path.exists(f"{chr(l)}:/")]
            if not drives:
                 self.info_event("No drives found to scan.")
                 return

            if not self.question_event(f"This will scan all files on drive(s): {', '.join(drives)}. This may take a long time. Continue?"):
                return

            # Define the target function to scan all drives
            def scan_all_drives(drive_list):
                 for drive in drive_list:
                     if not self.scan_file: break # Check if scan was stopped
                     print(f"Scanning drive: {drive}")
                     # Update UI text to show current drive
                     QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, f"Scanning drive {drive}..."))
                     self.traverse_path(drive) # Scan the root of the drive

            # Run the full scan in a thread
            self._run_scan_thread(scan_all_drives, drives)

        except Exception as e:
            print(f"Error during disk scan setup: {e}")
            self.virus_scan_break()


    def traverse_path(self, root_path): # Recursively traverse directory and scan files
        """Traverses a path, scanning files and subdirectories."""
        try:
            # Use os.scandir for potentially better performance
            for entry in os.scandir(root_path):
                if not self.scan_file: # Check if scan cancelled
                    print("Traversal stopped.")
                    break
                try:
                    file_path = entry.path.replace("\\", "/")

                    # Check whitelist before proceeding
                    if self.check_whitelist(file_path):
                        # print(f"Skipping whitelisted: {file_path}") # Optional debug log
                        continue

                    # Update UI with current scanning location (use invokeMethod for thread safety)
                    # Throttle UI updates to avoid performance impact
                    if self.total_scan % 50 == 0: # Update every 50 files
                         QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText", Qt.QueuedConnection, Q_ARG(str, file_path))

                    if entry.is_dir(follow_symlinks=False):
                         self.traverse_path(file_path) # Recurse into subdirectory
                    elif entry.is_file(follow_symlinks=False):
                         # Scan the file
                         scan_result = self.start_scan(file_path)
                         self.write_scan(scan_result, file_path) # Add result if threat found
                         self.total_scan += 1

                except PermissionError:
                    # print(f"Permission denied: {file_path}")
                    pass # Skip files/folders we can't access
                except FileNotFoundError:
                    # print(f"File not found during scan (maybe deleted?): {file_path}")
                    pass # File might have been deleted between scandir and access
                except Exception as traverse_err:
                    print(f"Error processing {entry.path}: {traverse_err}")
        except PermissionError:
             print(f"Permission denied accessing root path: {root_path}")
        except FileNotFoundError:
             print(f"Path not found: {root_path}")
        except Exception as e:
            print(f"Error traversing path {root_path}: {e}")


    def start_scan(self, file_path): # Call scan engines (DL and YARA)
        """Scans a file using configured engines and returns the result label/level."""
        primary_result = None
        secondary_result = None

        # 1. Deep Learning Scan (Primary)
        try:
            label, level = self.model.dl_scan(file_path)
            if label: # If DL engine detected something
                 # Check sensitivity level
                 is_sensitive = self.config_json.get("sensitivity", 0) == 1
                 # Assume self.model.values holds the threshold for "Medium" sensitivity
                 medium_threshold = getattr(self.model, 'values', 0.75) # Default threshold if not set

                 # Report if high sensitivity is on, OR if level meets medium threshold
                 if is_sensitive or (level >= medium_threshold):
                     primary_result = f"{label}.DL{int(level*100)}" # e.g., Malware.DL85

        except Exception as e:
            # Log DL scan errors but don't stop the whole process
            print(f"Error during DL scan for {file_path}: {e}")

        # 2. YARA Rules Scan (Secondary/Extended) - Only if enabled and no primary result yet (optional logic)
        # You might want YARA to run always, even if DL found something, to add more info.
        # Let's run it if enabled, regardless of DL result for now.
        if self.config_json.get("extend_mode", 0) == 1:
            try:
                # Assuming yr_scan returns (label, match_string or None)
                label, match_info = self.rules.yr_scan(file_path)
                if label and match_info:
                    # Format YARA result (e.g., RuleName.SignatureName)
                    secondary_result = f"{label}.YR_{match_info}" # Example format

            except Exception as e:
                 print(f"Error during YARA scan for {file_path}: {e}")

        # --- Decide final result ---
        # Prioritize primary (DL) result if available? Or combine?
        # Let's prioritize DL if it triggered based on sensitivity.
        if primary_result:
             return primary_result
        elif secondary_result:
             return secondary_result
        else:
             return False # No threat detected by enabled engines


    # --- System Repair Functions ---

    def repair_system(self): # Main function to trigger system repairs
        try:
            if self.question_event("This will attempt to repair common system file associations, restrictions, and registry settings. Are you sure?"):
                self.info_event("Starting system repair...")
                QApplication.processEvents() # Update UI

                success_count = 0
                fail_count = 0

                # Define repair steps
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
                    QApplication.processEvents() # Keep UI responsive

                # Final report
                if fail_count == 0:
                    self.info_event(f"System repair completed successfully ({success_count} steps). A restart may be required for all changes.")
                else:
                    self.info_event(f"System repair finished. Success: {success_count}, Failures: {fail_count}. Check console for details. A restart may be required.")

        except Exception as e:
            print(f"Error during system repair process: {e}")
            self.info_event("An error occurred during system repair.")


    # --- Registry Helper Functions ---
    # Define HKEY constants
    HKEY_CLASSES_ROOT = 0x80000000
    HKEY_CURRENT_USER = 0x80000001
    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_USERS = 0x80000003

    # Define KEY access rights
    KEY_READ = 0x20019
    KEY_WRITE = 0x20006
    KEY_ALL_ACCESS = 0xF003F

    def open_registry_key(self, hkey_root, subkey_path, access=KEY_READ):
        """Opens a registry key and returns the handle."""
        key_handle = ctypes.wintypes.HKEY()
        try:
            result = self.advapi32.RegOpenKeyExW(
                hkey_root,        # hKey (root HKEY constant)
                subkey_path,      # lpSubKey
                0,                # ulOptions (reserved)
                access,           # samDesired (access rights)
                ctypes.byref(key_handle) # phkResult
            )
            if result == 0: # ERROR_SUCCESS
                return key_handle
            else:
                # print(f"Failed to open key {subkey_path}. Error code: {result}")
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
        # This function in Windows API deletes a key relative to an OPEN handle.
        # Or it can delete a key directly using RegDeleteKeyExW if we know the parent path.
        # Let's use the approach requiring an open parent handle with WRITE access.
        try:
            # Assume hkey_root_or_handle is an already opened handle to the PARENT key
            result = self.advapi32.RegDeleteKeyW(hkey_root_or_handle, subkey_name)
            if result == 0:
                print(f"Deleted registry key: {subkey_name}")
                # Check if triggered by a tracked process during protection
                if self.track_proc and self.config_json.get("sys_protect",0):
                    self.kill_process("Registry Tampering (Key Deletion)", *self.track_proc)
                return True
            else:
                # print(f"Failed to delete registry key {subkey_name}. Error code: {result}")
                return False
        except Exception as e:
            print(f"Exception deleting registry key {subkey_name}: {e}")
            return False


    def delete_registry_value(self, hkey_handle, value_name):
        """Deletes a registry value from an open key handle."""
        try:
            result = self.advapi32.RegDeleteValueW(hkey_handle, value_name)
            if result == 0:
                # print(f"Deleted registry value: {value_name}")
                # Check if triggered by a tracked process during protection
                if self.track_proc and self.config_json.get("sys_protect",0):
                    self.kill_process("Registry Tampering (Value Deletion)", *self.track_proc)
                return True
            elif result == 2: # ERROR_FILE_NOT_FOUND - Value doesn't exist, not an error for repair
                 return True
            else:
                # print(f"Failed to delete registry value {value_name}. Error code: {result}")
                return False
        except Exception as e:
            print(f"Exception deleting registry value {value_name}: {e}")
            return False


    def create_registry_key(self, hkey_root, subkey_path):
        """Creates a registry key if it doesn't exist."""
        key_handle = ctypes.wintypes.HKEY()
        disposition = ctypes.wintypes.DWORD() # Will be REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY
        try:
            result = self.advapi32.RegCreateKeyExW(
                hkey_root,        # hKey
                subkey_path,      # lpSubKey
                0,                # Reserved
                None,             # lpClass
                0,                # dwOptions (REG_OPTION_NON_VOLATILE)
                self.KEY_WRITE,   # samDesired
                None,             # lpSecurityAttributes
                ctypes.byref(key_handle), # phkResult
                ctypes.byref(disposition) # lpdwDisposition
            )
            if result == 0:
                 self.close_registry_key(key_handle) # Close handle after creation/opening
                 # print(f"Ensured registry key exists: {subkey_path}")
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
            # Try creating the key first? Might be needed for repair.
            if self.create_registry_key(hkey_root, subkey_path):
                 key_handle = self.open_registry_key(hkey_root, subkey_path, self.KEY_WRITE)
                 if not key_handle:
                      print(f"Still cannot open key {subkey_path} after attempting creation.")
                      return False
            else:
                 return False # Failed to create key

        try:
            if value_type == 1: # REG_SZ (String)
                value_buffer = ctypes.create_unicode_buffer(value_data)
                # Size includes null terminator, hence (len + 1) * size_of_WCHAR
                data_size = (len(value_data) + 1) * ctypes.sizeof(ctypes.wintypes.WCHAR)
            # Add other types (DWORD=4 etc.) if needed
            # elif value_type == 4: # REG_DWORD
            #    value_buffer = ctypes.c_ulong(value_data)
            #    data_size = ctypes.sizeof(value_buffer)
            else:
                print(f"Unsupported registry value type: {value_type}")
                self.close_registry_key(key_handle)
                return False

            result = self.advapi32.RegSetValueExW(
                key_handle,       # hKey
                value_name,       # lpValueName
                0,                # Reserved
                value_type,       # dwType
                ctypes.byref(value_buffer), # lpData
                data_size         # cbData
            )
            if result == 0:
                # print(f"Set registry value '{value_name}' in {subkey_path}")
                # No process killing check here, as setting values is often legitimate repair
                return True
            else:
                print(f"Failed to set registry value '{value_name}' in {subkey_path}. Error code: {result}")
                return False
        except Exception as e:
            print(f"Exception setting registry value '{value_name}' in {subkey_path}: {e}")
            return False
        finally:
            self.close_registry_key(key_handle)


    # --- Specific Repair Implementations ---

    def repair_system_restrict(self): # Repair common policy restrictions
        """Removes common UI/system restrictions from Policies keys."""
        # List of common restriction value names
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
            "NoStartMenuNetworkPlaces", "Wallpaper" # Wallpaper policy is also a restriction
        ]
        # Target registry keys where these restrictions are often set
        policy_keys = [
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
            (self.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"),
            (self.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\System"), # Group Policy location
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"),
            (self.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System"), # Group Policy location
            # MMC restrictions (less common for general users, but malware might use)
            # (HKEY_CURRENT_USER, r"Software\Policies\Microsoft\MMC"),
            # (HKEY_CURRENT_USER, r"Software\Policies\Microsoft\MMC\{specific_snapin_clsid}")
        ]

        for hkey, subkey in policy_keys:
            key_handle = self.open_registry_key(hkey, subkey, self.KEY_WRITE)
            if key_handle:
                # print(f"Checking restrictions in: HKEY {hkey} \\ {subkey}")
                for value_name in restrictions:
                    # Attempt to delete the value
                    self.delete_registry_value(key_handle, value_name)
                self.close_registry_key(key_handle)
            # else: Key doesn't exist or cannot be opened, which is fine for repair.


    def repair_system_image(self): # Repair Image File Execution Options (IFEO) hijacks
        """Removes debugger entries from IFEO keys, except known safe ones."""
        ifeo_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        # List known legitimate debuggers or tools that use IFEO (case-insensitive)
        # Example: Add Windows Error Reporting, Process Explorer, etc. if needed
        known_safe_exes = ['procexp.exe', 'procexp64.exe', 'werfault.exe']

        key_handle = self.open_registry_key(self.HKEY_LOCAL_MACHINE, ifeo_path, self.KEY_ALL_ACCESS)
        if not key_handle:
            print(f"Could not open IFEO key: {ifeo_path}")
            return

        try:
            # Get number of subkeys
            num_subkeys = ctypes.wintypes.DWORD()
            self.advapi32.RegQueryInfoKeyW(key_handle, None, None, None, ctypes.byref(num_subkeys),
                                            None, None, None, None, None, None, None)

            # Iterate through subkeys (executable names)
            for i in range(num_subkeys.value):
                subkey_name_buffer = ctypes.create_unicode_buffer(260) # Max path length for exe name
                subkey_name_len = ctypes.wintypes.DWORD(260)
                result = self.advapi32.RegEnumKeyExW(key_handle, i, subkey_name_buffer,
                                                     ctypes.byref(subkey_name_len), None, None, None, None)

                if result == 0: # Success getting subkey name
                    exe_name = subkey_name_buffer.value
                    # Skip known safe executables
                    if exe_name.lower() in known_safe_exes:
                         # print(f"Skipping known safe IFEO entry: {exe_name}")
                         continue

                    # Open the executable's subkey
                    exe_key_path = os.path.join(ifeo_path, exe_name).replace("\\","/") # Build full path for opening
                    exe_key_handle = self.open_registry_key(self.HKEY_LOCAL_MACHINE, exe_key_path, self.KEY_READ | self.KEY_WRITE)

                    if exe_key_handle:
                        # Check if a "Debugger" value exists
                        debugger_value_buffer = ctypes.create_unicode_buffer(1024)
                        debugger_value_size = ctypes.wintypes.DWORD(1024 * ctypes.sizeof(ctypes.wintypes.WCHAR))
                        debugger_value_type = ctypes.wintypes.DWORD()

                        value_result = self.advapi32.RegQueryValueExW(
                            exe_key_handle, "Debugger", None, ctypes.byref(debugger_value_type),
                            ctypes.cast(debugger_value_buffer, ctypes.POINTER(ctypes.wintypes.BYTE)),
                            ctypes.byref(debugger_value_size)
                        )

                        if value_result == 0: # Debugger value exists
                             print(f"Removing potential hijack for {exe_name} (Debugger: {debugger_value_buffer.value})")
                             # Delete the "Debugger" value
                             self.delete_registry_value(exe_key_handle, "Debugger")
                             # Optionally: Delete the entire exe key if it only contained 'Debugger'? Risky.
                             # self.delete_registry_key(key_handle, exe_name) # Deleting the whole key is safer if IFEO is abused

                        self.close_registry_key(exe_key_handle)
                    else:
                         print(f"Warning: Could not open IFEO subkey {exe_name} to check for debugger.")

                # elif result == 259: # ERROR_NO_MORE_ITEMS - Should not happen inside loop range?
                #    break
                else:
                    print(f"Error enumerating IFEO subkey at index {i}. Error code: {result}")

        except Exception as e:
            print(f"Exception processing IFEO entries: {e}")
        finally:
            self.close_registry_key(key_handle)


    def repair_system_file_icon(self): # Repair default icon for EXE files
        """Resets the default icon for .exe files."""
        try:
            # HKCR is a merged view, setting in HKLM\Software\Classes is usually sufficient
            base_path = r'SOFTWARE\Classes'
            exe_key = r'exefile\DefaultIcon'
            default_icon_value = r'%1' # Use placeholder for the executable itself

            # Set in HKLM (affects all users)
            self.set_registry_value(self.HKEY_LOCAL_MACHINE, os.path.join(base_path, exe_key), "", default_icon_value)

            # Optional: Set in HKCU (overrides HKLM for current user) - usually not needed for repair
            # self.set_registry_value(self.HKEY_CURRENT_USER, os.path.join(base_path, exe_key), "", default_icon_value)

            # Optional: Force icon cache refresh (might require restart or logout/login)
            # This is complex, often involves deleting IconCache.db and restarting explorer

        except Exception as e:
            print(f"Error repairing file icon: {e}")


    def repair_system_file_type(self): # Repair file associations for EXE files
        """Repairs .exe file association and open command."""
        try:
            # HKLM is the primary place for system-wide associations
            hkey = self.HKEY_LOCAL_MACHINE
            base_path = r'SOFTWARE\Classes'

            # 1. Ensure .exe maps to 'exefile' ProgID
            self.set_registry_value(hkey, os.path.join(base_path, '.exe'), "", 'exefile')

            # 2. Ensure 'exefile' has correct default description (optional but good practice)
            self.set_registry_value(hkey, os.path.join(base_path, 'exefile'), "", 'Application')

            # 3. Ensure 'exefile' has correct 'open' command
            open_command_path = os.path.join(base_path, r'exefile\shell\open\command')
            open_command_value = r'"%1" %*' # Standard command: executable path followed by arguments
            self.set_registry_value(hkey, open_command_path, "", open_command_value)

            # Optional: Set in HKCU as well? Usually HKLM is enough.
            # Optional: Notify shell of changes (SHChangeNotify) - complex ctypes call

        except Exception as e:
            print(f"Error repairing file type association: {e}")


    def repair_system_wallpaper(self): # Reset wallpaper to Windows default
        """Resets the desktop wallpaper to the default Windows image."""
        try:
            # Default wallpaper path (adjust if needed for different Windows versions)
            default_wallpaper = r"C:\Windows\Web\Wallpaper\Windows\img0.jpg"

            if not os.path.exists(default_wallpaper):
                print("Default wallpaper image not found. Skipping wallpaper reset.")
                # Maybe try finding another default? C:\Windows\Web\screen\img100.jpg ?
                return

            # Set wallpaper path in registry (for current user)
            wallpaper_key = r"Control Panel\Desktop"
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "Wallpaper", default_wallpaper)

            # Set style (e.g., Stretch=2, Tile=0, Center=?) - Tile is often default
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "WallpaperStyle", "0") # 0 for Tile
            self.set_registry_value(self.HKEY_CURRENT_USER, wallpaper_key, "TileWallpaper", "1")  # 1 for Tile=True

            # Apply the change immediately using SystemParametersInfo
            SPI_SETDESKWALLPAPER = 0x0014
            SPIF_UPDATEINIFILE = 0x01 # Write change to user profile
            SPIF_SENDCHANGE = 0x02     # Broadcast WM_SETTINGCHANGE

            result = self.user32.SystemParametersInfoW(
                SPI_SETDESKWALLPAPER,
                0,                     # uiParam (not used for setting wallpaper path)
                default_wallpaper,     # pvParam (path to wallpaper)
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE # fWinIni options
            )
            if not result:
                 print(f"SystemParametersInfo failed to set wallpaper. Error: {ctypes.get_last_error()}")

        except Exception as e:
            print(f"Error repairing wallpaper: {e}")


    def repair_network(self): # Reset network stack (netsh winsock reset)
        """Resets Winsock and prompts for restart."""
        try:
            if self.question_event("This will reset the network configuration (Winsock). You will likely need to restart your computer. Are you sure?"):
                self.info_event("Running 'netsh winsock reset'...")
                QApplication.processEvents() # Update UI

                # Execute the command, wait for completion, capture output
                process = Popen("netsh winsock reset", shell=True, stdout=PIPE, stderr=PIPE, text=True, creationflags=CREATE_NO_WINDOW)
                stdout, stderr = process.communicate()
                exit_code = process.wait()

                if exit_code == 0:
                    print("Winsock reset successful.")
                    if self.question_event("Network reset completed successfully. Restart required to apply changes. Restart now?"):
                        self.info_event("Restarting computer...")
                        Popen("shutdown -r -t 5 -c \"PYAS requested restart after network repair.\"", shell=True, stdout=PIPE, stderr=PIPE, creationflags=CREATE_NO_WINDOW)
                        # Application will likely close before command executes fully
                        self.close() # Close the app gracefully before restart
                    else:
                         self.info_event("Network reset complete. Please restart your computer manually.")
                else:
                    self.info_event(f"Network reset command failed (Exit Code: {exit_code}).\nError: {stderr}")

        except FileNotFoundError:
             self.info_event("Error: 'netsh' command not found. Cannot reset network.")
        except Exception as e:
            print(f"Error during network repair: {e}")
            self.info_event("An error occurred during network repair.")


    def clean_system(self): # Clean temporary files and Recycle Bin
        """Cleans system temporary folders and optionally the Recycle Bin."""
        try:
            # Define paths to clean
            paths_to_clean = []
            # Windows Temp
            paths_to_clean.append(os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "Temp"))
            # User Temp
            paths_to_clean.append(os.environ.get("TEMP", ""))
            # Optional: Add Prefetch, SoftwareDistribution download cache? Be cautious.
            # paths_to_clean.append(os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "Prefetch"))

            # Clean Recycle Bin (requires external library or complex WinAPI)
            # Using 'winshell' library as an example (pip install winshell)
            clean_recycle_bin = False
            try:
                import winshell
                if self.question_event("Do you also want to empty the Recycle Bin?"):
                    clean_recycle_bin = True
            except ImportError:
                 print("Optional: 'winshell' library not found. Skipping Recycle Bin cleaning.")
                 # pip install winshell

            # Confirmation
            if self.question_event("This will delete files from temporary locations. Are you sure?"):
                self.info_event("Starting system cleaning...")
                QApplication.processEvents()

                self.total_deleted_size = 0
                self.total_deleted_count = 0
                self.total_failed_count = 0

                # Clean defined paths
                for path in paths_to_clean:
                    if path and os.path.isdir(path):
                        print(f"Cleaning path: {path}")
                        self.traverse_and_delete(path)
                    else:
                         print(f"Skipping invalid or non-existent path: {path}")

                # Clean Recycle Bin if requested and possible
                if clean_recycle_bin:
                     try:
                         print("Emptying Recycle Bin...")
                         winshell.recycle_bin().empty(confirm=False, show_progress=False, sound=False)
                         print("Recycle Bin emptied.")
                     except Exception as rb_err:
                         print(f"Failed to empty Recycle Bin: {rb_err}")
                         self.total_failed_count += 1 # Count failure

                # Report results
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
                QApplication.processEvents() # Keep UI responsive

                if entry.is_file(follow_symlinks=False):
                    file_size = entry.stat().st_size
                    os.remove(entry.path)
                    self.total_deleted_size += file_size
                    self.total_deleted_count += 1
                    # Optional: Update UI with current file being deleted? Might slow down.
                    # if self.total_deleted_count % 100 == 0: print(f"Deleted {self.total_deleted_count} files...")

                elif entry.is_dir(follow_symlinks=False):
                     # Recursively delete content first
                     self.traverse_and_delete(entry.path)
                     # Then delete the empty directory
                     os.rmdir(entry.path)
                     # print(f"Removed directory: {entry.path}") # Optional log

            except PermissionError:
                # print(f"Permission denied deleting: {entry.path}")
                self.total_failed_count += 1
            except OSError as os_err:
                # Handle cases like "directory not empty" (shouldn't happen with recursion)
                # Or file in use
                # print(f"OS error deleting {entry.path}: {os_err}")
                self.total_failed_count += 1
            except Exception as del_err:
                print(f"Unexpected error deleting {entry.path}: {del_err}")
                self.total_failed_count += 1


    # --- Real-time Protection Threads ---

    def protect_proc_thread(self): # Process creation monitoring thread
        """Monitors for new processes and scans them."""
        print("Process protection thread started.")
        while self.config_json.get("proc_protect", 0) == 1:
            try:
                time.sleep(0.1) # Check interval
                current_process_set = self.get_process_list()
                if current_process_set is None: continue # Skip if error getting list

                # Find newly created processes (difference between current and last known set)
                new_pids = current_process_set - self.exist_process

                if new_pids:
                     # print(f"New processes detected: {new_pids}")
                     for pid in new_pids:
                          if pid == 0 or pid == 4: continue # Skip System Idle and System process
                          self.handle_new_process(pid)

                # Update the known process set for the next iteration
                self.exist_process = current_process_set

            except Exception as e:
                print(f"Error in process protection thread: {e}")
                time.sleep(1) # Wait longer after an error
        print("Process protection thread stopped.")


    def get_process_list(self): # Get current set of Process IDs (PIDs)
        """Returns a set of all current process IDs."""
        try:
            pid_set = set()
            # Allocate buffer for process IDs
            # Start with a reasonable size, e.g., 1024 PIDs (DWORD = 4 bytes)
            buffer_size = 1024 * ctypes.sizeof(ctypes.wintypes.DWORD)
            process_ids = (ctypes.wintypes.DWORD * 1024)()
            bytes_returned = ctypes.wintypes.DWORD()

            # Call EnumProcesses
            if self.psapi.EnumProcesses(ctypes.byref(process_ids), buffer_size, ctypes.byref(bytes_returned)):
                # Check if buffer was large enough
                if bytes_returned.value >= buffer_size:
                     # Buffer might have been too small, try again with larger buffer
                     # Calculate required size (bytes_returned gives needed size)
                     new_size = bytes_returned.value
                     num_pids_estimated = new_size // ctypes.sizeof(ctypes.wintypes.DWORD)
                     process_ids = (ctypes.wintypes.DWORD * num_pids_estimated)()
                     buffer_size = new_size
                     if not self.psapi.EnumProcesses(ctypes.byref(process_ids), buffer_size, ctypes.byref(bytes_returned)):
                          print(f"Failed EnumProcesses even after resize. Error: {ctypes.get_last_error()}")
                          return None # Failed to get list
                     # Recalculate actual number of PIDs returned after resize
                     num_pids = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)
                else:
                     num_pids = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)

                # Populate the set
                for i in range(num_pids):
                    pid_set.add(process_ids[i])

                return pid_set
            else:
                print(f"Failed EnumProcesses. Error: {ctypes.get_last_error()}")
                return None
        except Exception as e:
            print(f"Exception getting process list: {e}")
            return None


    def handle_new_process(self, pid): # Scan a newly detected process
        """Opens, scans, and potentially terminates a new process."""
        h_process = None # Ensure h_process is defined
        try:
            # --- Open Process Handle ---
            # Request necessary permissions: Query Info, VM Read, Suspend/Resume, Terminate
            access_flags = 0x1000 | 0x0400 | 0x0010 | 0x0002 | 0x0001 # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE
            h_process = self.kernel32.OpenProcess(access_flags, False, pid)

            if not h_process:
                 # print(f"Could not open process {pid} (Permissions?). Skipping.")
                 return

            # --- Get Process File Path ---
            file_path = self.get_process_file(h_process)
            if not file_path or not os.path.exists(file_path):
                # print(f"Could not get valid path for PID {pid}. Skipping.")
                self.kernel32.CloseHandle(h_process)
                return

            file_path = file_path.replace("\\", "/") # Normalize path

            # --- Whitelist Check ---
            if self.check_whitelist(file_path):
                # print(f"Process whitelisted: {file_path} (PID: {pid})")
                self.kernel32.CloseHandle(h_process)
                return

            # --- Suspend Process (Optional but recommended before scanning) ---
            # print(f"Suspending PID {pid} for scanning...")
            self.lock_process(h_process, True) # True = Suspend

            # --- Scan File ---
            scan_result = self.start_scan(file_path)

            # --- Handle Scan Result ---
            if scan_result: # Threat detected
                 print(f"Threat detected in new process: {scan_result} - {file_path} (PID: {pid})")
                 # Kill the process (already suspended)
                 self.kill_process("Process Threat Intercepted", h_process, file_path)
                 # kill_process closes the handle, so don't close it again
                 h_process = None # Mark handle as closed
            else:
                 # No threat found, resume process
                 # print(f"No threat found in PID {pid}. Resuming...")
                 self.lock_process(h_process, False) # False = Resume
                 # Store handle/path as potentially malicious for further monitoring (if sys/file protect enabled)
                 # Check if system drive process for different tracking level?
                 # Simplified: Track all non-whitelisted processes that were scanned
                 self.track_proc = (h_process, file_path)
                 # Note: The handle in track_proc needs to be closed eventually if the process exits normally.
                 # This simple tracking mechanism doesn't handle that lifecycle well.
                 # A better approach would store PID and reopen handle when needed.
                 # For now, let's keep it simple but be aware of potential handle leaks if tracked processes live long.
                 # We will just close the handle here, and reopen if needed in other protections.
                 self.kernel32.CloseHandle(h_process)
                 self.track_proc = (pid, file_path) # Store PID and path instead of handle
                 h_process = None


        except Exception as e:
            print(f"Error handling new process PID {pid}: {e}")
            # Ensure process is resumed and handle closed on error
            if h_process:
                try:
                    self.lock_process(h_process, False) # Attempt resume
                except: pass
                try:
                    self.kernel32.CloseHandle(h_process)
                except: pass
            self.track_proc = None # Clear tracking on error


    def check_whitelist(self, file_or_dir_path):
        """Checks if a given path is within any whitelisted path."""
        try:
            normalized_path = os.path.normpath(file_or_dir_path).lower()
            # Ensure whitelist exists and is a list
            current_whitelist = self.config_json.get("white_lists", [])
            if not isinstance(current_whitelist, list): return False

            for white_item in current_whitelist:
                normalized_white_item = os.path.normpath(white_item).lower()
                # Check if the path *is* the whitelist item or *starts with* the whitelist item + separator
                if normalized_path == normalized_white_item or \
                   normalized_path.startswith(normalized_white_item + os.path.sep):
                    return True
            return False
        except Exception as e:
            print(f"Error checking whitelist for {file_or_dir_path}: {e}")
            return False # Treat as not whitelisted on error


    def kill_process(self, reason, process_pid_or_handle, file_path):
        """Terminates a process identified by PID or handle."""
        pid_to_kill = -1
        handle_to_close = None

        if isinstance(process_pid_or_handle, int): # It's a PID
            pid_to_kill = process_pid_or_handle
            # Try to open handle with terminate permission
            handle_to_close = self.kernel32.OpenProcess(0x0001, False, pid_to_kill) # PROCESS_TERMINATE
        elif hasattr(process_pid_or_handle, 'value'): # Assume it's a ctypes handle (like HPROCESS)
            handle_to_close = process_pid_or_handle
            # Get PID from handle if possible (requires QueryLimitedInfo)
            # pid_buffer = ctypes.wintypes.DWORD()
            # if self.kernel32.GetProcessId(handle_to_close): pid_to_kill = ...
            # For simplicity, we might not have the PID here if only handle was passed.
        else:
            print(f"Invalid identifier for kill_process: {process_pid_or_handle}")
            return

        try:
            if handle_to_close:
                success = self.kernel32.TerminateProcess(handle_to_close, 1) # Exit code 1
                if success:
                    log_msg = f"{reason}: Terminated process '{os.path.basename(file_path)}'"
                    if pid_to_kill != -1: log_msg += f" (PID: {pid_to_kill})"
                    self.send_notify(log_msg, True)
                else:
                    # Get error if termination failed
                    error_code = ctypes.get_last_error()
                    print(f"Failed to terminate process {file_path} (PID: {pid_to_kill}). Error: {error_code}")
                # Always close the handle we used/opened
                self.kernel32.CloseHandle(handle_to_close)
            else:
                 print(f"Could not get handle to terminate process PID {pid_to_kill}.")

        except Exception as e:
            print(f"Exception during kill_process for {file_path}: {e}")
            # Ensure handle is closed even if TerminateProcess raises exception
            if handle_to_close:
                 try: self.kernel32.CloseHandle(handle_to_close)
                 except: pass
        finally:
            # Clear the tracked process if it matches the killed one
             if self.track_proc and isinstance(self.track_proc[0], int) and self.track_proc[0] == pid_to_kill:
                  self.track_proc = None
             elif self.track_proc and self.track_proc[1] == file_path: # Fallback check by path
                  self.track_proc = None


    def lock_process(self, h_process, lock): # Suspend/Resume a process
        """Suspends (lock=True) or resumes (lock=False) a process using NtSuspendProcess/NtResumeProcess."""
        try:
            if lock:
                result = self.ntdll.NtSuspendProcess(h_process)
                # if result != 0: print(f"NtSuspendProcess failed with status {result:#010x}")
            else:
                result = self.ntdll.NtResumeProcess(h_process)
                # if result != 0: print(f"NtResumeProcess failed with status {result:#010x}")
            # Status 0 indicates success for NTSTATUS functions
            return result == 0
        except Exception as e:
            print(f"Exception in lock_process (NtSuspend/Resume): {e}")
            return False


    def get_process_file(self, h_process): # Get executable path from process handle
        """Gets the full path of the executable file for a given process handle."""
        if not h_process: return None
        try:
            # Use QueryFullProcessImageName for more reliable path retrieval
            exe_path_buffer = ctypes.create_unicode_buffer(1024)
            buffer_size = ctypes.wintypes.DWORD(1024) # Size in characters

            if self.kernel32.QueryFullProcessImageNameW(h_process, 0, exe_path_buffer, ctypes.byref(buffer_size)):
                 full_path = exe_path_buffer.value
                 # This path might still be in NT device format (\Device\HarddiskVolumeX\...)
                 # Convert device path to drive letter path if possible
                 return self._device_path_to_drive_path(full_path)
            else:
                # Fallback using GetProcessImageFileNameW (less reliable, needs Psapi.dll)
                fallback_buffer = ctypes.create_unicode_buffer(1024)
                if self.psapi.GetProcessImageFileNameW(h_process, fallback_buffer, 1024) > 0:
                     # This returns NT device path, needs conversion
                     return self._device_path_to_drive_path(fallback_buffer.value)
                else:
                     # print(f"Could not get process image path. Error: {ctypes.get_last_error()}")
                     return None

        except Exception as e:
            print(f"Exception getting process file path: {e}")
            return None

    def _device_path_to_drive_path(self, device_path):
        """Converts an NT device path (e.g., \\Device\\HarddiskVolumeX\\...) to a drive letter path."""
        if not device_path: return device_path

        # Get drive strings (e.g., "C:", "D:")
        drive_buffer_len = self.kernel32.GetLogicalDriveStringsW(0, None)
        if drive_buffer_len == 0: return device_path # Error getting drives
        drive_buffer = ctypes.create_unicode_buffer(drive_buffer_len)
        if self.kernel32.GetLogicalDriveStringsW(drive_buffer_len, drive_buffer) == 0:
             return device_path # Error getting drives

        # Split the buffer into individual drive roots (like "C:\", "D:\")
        drives = [drive for drive in drive_buffer.value.split('\0') if drive]

        # Check each drive letter mapping
        target_path_buffer = ctypes.create_unicode_buffer(1024)
        for drive in drives:
            drive_letter = drive[:2] # "C:"
            # Get the device path associated with this drive letter
            if self.kernel32.QueryDosDeviceW(drive_letter, target_path_buffer, 1024) != 0:
                 mapped_device = target_path_buffer.value
                 # Check if the input device_path starts with this mapping
                 if device_path.startswith(mapped_device):
                      # Replace the device part with the drive letter
                      return device_path.replace(mapped_device, drive_letter, 1)

        # If no mapping found, return the original path (might be UNC or already drive letter)
        return device_path


    def protect_file_thread(self): # File system monitoring thread
        """Monitors file system changes using ReadDirectoryChangesW."""
        print("File protection thread started.")
        self.ransom_counts = 0 # Counter for suspicious rename/modify actions
        hDir = None # Ensure hDir is defined

        # Define flags for ReadDirectoryChangesW
        FILE_LIST_DIRECTORY = 0x0001
        FILE_NOTIFY_CHANGE_FILE_NAME = 0x0001   # Renames, Creates
        FILE_NOTIFY_CHANGE_DIR_NAME = 0x0002    # Renames, Creates
        FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x0004
        FILE_NOTIFY_CHANGE_SIZE = 0x0008
        FILE_NOTIFY_CHANGE_LAST_WRITE = 0x0010  # Content changes
        FILE_NOTIFY_CHANGE_SECURITY = 0x0100

        # Actions from FILE_NOTIFY_INFORMATION
        FILE_ACTION_ADDED = 1
        FILE_ACTION_REMOVED = 2
        FILE_ACTION_MODIFIED = 3
        FILE_ACTION_RENAMED_OLD_NAME = 4
        FILE_ACTION_RENAMED_NEW_NAME = 5

        # Monitor flags (adjust as needed)
        # Monitor file/dir renames, file writes/size changes
        monitor_flags = (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                         FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE)

        try:
            # --- Open Handle to Drive Root (e.g., C:\) ---
            # Use FILE_LIST_DIRECTORY access right
            # Flags: FILE_FLAG_BACKUP_SEMANTICS is required for monitoring directories
            drive_to_monitor = "C:\\" # Monitor C drive
            hDir = self.kernel32.CreateFileW(
                drive_to_monitor,
                FILE_LIST_DIRECTORY,
                0x00000001 | 0x00000002 | 0x00000004, # Share Read/Write/Delete
                None,                                # Security Attributes
                3,                                   # OPEN_EXISTING
                0x02000000 | 0x00000010,             # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED (can be used for async) - Using synchronous here
                None                                 # Template File
            )

            if not hDir or hDir == -1: # INVALID_HANDLE_VALUE = -1
                print(f"Failed to open handle to {drive_to_monitor}. Error: {ctypes.get_last_error()}. File protection disabled.")
                self.config_json["file_protect"] = 0 # Disable in config if handle fails
                self.init_config_write(self.config_json)
                # Update UI button state? Needs main thread invoke.
                return # Exit thread

            # Buffer for notifications
            buffer_size = 4096 # Increased buffer size
            buffer = ctypes.create_string_buffer(buffer_size)
            bytesReturned = ctypes.wintypes.DWORD()

            while self.config_json.get("file_protect", 0) == 1:
                # --- Call ReadDirectoryChangesW ---
                success = self.kernel32.ReadDirectoryChangesW(
                    hDir,             # hDirectory
                    ctypes.byref(buffer), # lpBuffer
                    buffer_size,      # nBufferLength
                    True,             # bWatchSubtree
                    monitor_flags,    # dwNotifyFilter
                    ctypes.byref(bytesReturned), # lpBytesReturned (set to NULL for sync) -> No, needed for sync processing too
                    None,             # lpOverlapped (NULL for synchronous)
                    None              # lpCompletionRoutine (NULL for synchronous)
                )

                if not success:
                     # Handle errors, e.g., buffer overflow, handle closed
                     error_code = ctypes.get_last_error()
                     print(f"ReadDirectoryChangesW failed. Error code: {error_code}")
                     if error_code == 6: # ERROR_INVALID_HANDLE
                          print("Directory handle became invalid. Stopping file protection.")
                          break # Exit loop
                     # Handle other errors? Maybe sleep and retry?
                     time.sleep(5)
                     continue

                if bytesReturned.value == 0:
                     # Timeout or no changes (shouldn't happen with sync unless error?)
                     continue

                # --- Process Notifications in Buffer ---
                offset = 0
                while True: # Loop through multiple notifications in one buffer read
                    # Cast buffer at current offset to FILE_NOTIFY_INFORMATION struct
                    notify_info = FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)

                    # Extract filename (WCHAR string)
                    filename_length_bytes = notify_info.FileNameLength
                    filename_offset = FILE_NOTIFY_INFORMATION.FileName.offset
                    # Calculate pointer to the start of the filename string
                    filename_ptr = ctypes.addressof(notify_info) + filename_offset
                    # Read WCHAR string using the length (in bytes)
                    raw_filename = ctypes.wstring_at(filename_ptr, filename_length_bytes // 2) # Length is in bytes, wstring_at needs char count

                    # Construct full path (relative to the monitored handle, C:\ in this case)
                    fpath = os.path.join(drive_to_monitor, raw_filename).replace("\\", "/")

                    # Get file extension
                    ftype = os.path.splitext(fpath)[-1].lower()

                    action = notify_info.Action

                    # --- Ransomware Heuristics (Example) ---
                    # Tracked process is stored as (pid, path)
                    current_tracked_pid = self.track_proc[0] if self.track_proc else None
                    current_tracked_path = self.track_proc[1] if self.track_proc else None

                    # Check if the tracked process is performing suspicious actions
                    suspicious_action = False
                    # Check for modification/rename of sensitive file types outside Temp/AppData
                    is_sensitive_area = (":/windows" in fpath.lower() and "/temp/" not in fpath.lower()) or \
                                         (":/users" in fpath.lower() and "/appdata/" not in fpath.lower())

                    if is_sensitive_area and ftype in file_types and action in [FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_OLD_NAME]:
                         suspicious_action = True
                         self.ransom_counts += 1
                         print(f"Suspicious action count: {self.ransom_counts} by PID {current_tracked_pid} on {fpath}")

                    # Threshold for ransom action
                    if self.ransom_counts >= 5 and current_tracked_pid:
                        print(f"Ransomware threshold reached by PID {current_tracked_pid} ({current_tracked_path}). Terminating.")
                        self.kill_process("Ransomware Behavior Detected", current_tracked_pid, current_tracked_path)
                        self.ransom_counts = 0 # Reset counter after killing
                        self.track_proc = None # Clear tracking


                    # --- Scan on Creation/Modification (Outside Program Files/Windows) ---
                    # Scan files created/modified outside typical system/program folders
                    is_user_or_other_area = not (":/windows" in fpath.lower() or \
                                                 ":/program files" in fpath.lower() or \
                                                 ":/program files (x86)" in fpath.lower())

                    if action in [FILE_ACTION_ADDED, FILE_ACTION_MODIFIED] and is_user_or_other_area:
                        # Check whitelist before scanning
                        if not self.check_whitelist(fpath):
                             # Check if file exists before scanning (it might be temporary)
                             if os.path.exists(fpath) and os.path.isfile(fpath):
                                 # print(f"Scanning created/modified file: {fpath}")
                                 scan_result = self.start_scan(fpath)
                                 if scan_result:
                                     print(f"Threat found in new/modified file: {scan_result} - {fpath}")
                                     # Delete the detected file immediately
                                     try:
                                         self.lock_file(fpath, False) # Unlock if locked by previous detection
                                         os.remove(fpath)
                                         self.send_notify(f"Threat Deleted (File Protect): {os.path.basename(fpath)} ({scan_result})", True)
                                         # If killed by tracked process, maybe kill process?
                                         if current_tracked_pid:
                                             self.kill_process("File Threat Created", current_tracked_pid, current_tracked_path)
                                             self.track_proc = None
                                     except Exception as del_err:
                                         print(f"Failed to delete detected file {fpath}: {del_err}")


                    # --- Move to next notification ---
                    if notify_info.NextEntryOffset == 0:
                        break # End of notifications in this buffer read
                    offset += notify_info.NextEntryOffset # Move offset to the next entry

            # Loop exited, likely because file_protect was set to 0

        except Exception as e:
            print(f"Error in file protection thread: {e}")
        finally:
             # --- Close Directory Handle ---
             if hDir and hDir != -1:
                 self.kernel32.CloseHandle(hDir)
                 print("Closed directory handle.")
        print("File protection thread stopped.")


    def protect_boot_thread(self): # MBR monitoring thread
        """Monitors the Master Boot Record for changes."""
        if not self.mbr_value:
            print("MBR protection thread not started: Initial MBR read failed or invalid.")
            return

        print("Boot protection thread started.")
        while self.config_json.get("sys_protect", 0) == 1:
            try:
                time.sleep(2) # Check interval (don't check too frequently)

                current_mbr = None
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                     current_mbr = f.read(512)

                # Check boot signature first
                if current_mbr[510:512] != b'\x55\xAA':
                     print("MBR boot signature invalid!")
                     # Trigger action based on tracked process
                     if self.track_proc:
                          pid, path = self.track_proc
                          print(f"Potential MBR tampering (invalid signature) by PID {pid} ({path}). Terminating.")
                          self.kill_process("MBR Tampering Detected (Signature)", pid, path)
                          self.track_proc = None
                     # Should we try to restore? Risky. For now, just alert/kill.
                     # break # Stop monitoring if MBR is fundamentally broken?

                # Compare current MBR with stored original MBR
                elif current_mbr != self.mbr_value:
                    print("MBR change detected!")
                    # Trigger action based on tracked process
                    pid_responsible = -1
                    path_responsible = "Unknown"
                    if self.track_proc:
                         pid_responsible, path_responsible = self.track_proc
                         print(f"Potential MBR tampering by PID {pid_responsible} ({path_responsible}).")
                         self.kill_process("MBR Tampering Detected (Content)", pid_responsible, path_responsible)
                         self.track_proc = None

                    # Attempt to restore original MBR
                    if self.question_event(f"MBR has been modified (potentially by PID {pid_responsible}). Restore original MBR?"):
                         try:
                              with open(r"\\.\PhysicalDrive0", "r+b") as f:
                                   f.seek(0)
                                   f.write(self.mbr_value)
                              self.send_notify("MBR restored to original state.", True)
                         except Exception as restore_err:
                              print(f"Failed to restore MBR: {restore_err}")
                              self.send_notify("Failed to restore MBR!", True)
                    # else: User chose not to restore

                # else: MBR is unchanged, continue loop

            except PermissionError:
                print("Permission denied accessing PhysicalDrive0 in boot protect thread. Stopping.")
                self.config_json["sys_protect"] = 0 # Disable protection if permissions lost
                self.init_config_write(self.config_json)
                # Update UI? Needs main thread invoke.
                break
            except Exception as e:
                print(f"Error in boot protection thread: {e}")
                time.sleep(5) # Wait longer after error

        print("Boot protection thread stopped.")


    def protect_reg_thread(self): # Periodic registry repair thread
        """Periodically runs registry repair functions if System Protection is enabled."""
        print("Registry protection thread started.")
        while self.config_json.get("sys_protect", 0) == 1:
            try:
                # Run repairs periodically (e.g., every 5 minutes?)
                # Running too often can be resource intensive.
                time.sleep(300) # 5 minutes

                print("Performing periodic registry check/repair...")
                # Call specific repair functions silently
                # We rely on the delete_registry_value/key functions to trigger kill_process if needed
                self.repair_system_image()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                # Wallpaper repair is less critical for protection, maybe skip periodic check?
                # self.repair_system_wallpaper()
                print("Periodic registry check/repair complete.")

            except Exception as e:
                print(f"Error in registry protection thread: {e}")
                time.sleep(60) # Wait longer after an error
        print("Registry protection thread stopped.")


    def get_connections_list(self):  # Get current TCP connections and owning PIDs
        """Returns a set of active TCP connections: {(PID, LocalAddr, RemoteAddr, State), ...}"""
        try:
            connections = set()
            dwSize = ctypes.wintypes.DWORD(0)
            AF_INET = 2 # Address family IPv4
            TCP_TABLE_OWNER_PID_ALL = 5 # Table class to get all connections with PIDs

            # --- Call GetExtendedTcpTable the first time to get the required size ---
            ret = self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

            # ERROR_INSUFFICIENT_BUFFER (122) is expected on the first call
            if ret != 122:
                print(f"Error getting TCP table size: {ctypes.WinError(ret)} ({ret})")
                return None # Return None or empty set on error?

            # --- Allocate buffer of the required size ---
            # Ensure size is not zero before allocating
            if dwSize.value == 0:
                 print("TCP table size reported as 0. No connections or error.")
                 return set() # Return empty set

            lpTcpTable = ctypes.create_string_buffer(dwSize.value)

            # --- Call GetExtendedTcpTable again with the allocated buffer ---
            ret = self.iphlpapi.GetExtendedTcpTable(ctypes.byref(lpTcpTable), ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

            if ret != 0: # NO_ERROR (0) expected on success
                print(f"Error getting TCP table data: {ctypes.WinError(ret)} ({ret})")
                return None

            # --- Process the returned table ---
            # The buffer starts with dwNumEntries (DWORD)
            num_entries = ctypes.cast(lpTcpTable, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            # The table data (array of MIB_TCPROW_OWNER_PID) starts after the count
            offset = ctypes.sizeof(ctypes.wintypes.DWORD)
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)

            for i in range(num_entries):
                entry_address = ctypes.addressof(lpTcpTable) + offset + (i * row_size)
                conn_entry = ctypes.cast(entry_address, ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents

                # Add relevant info to the set (PID, Local IP, Remote IP, State)
                connections.add((
                    conn_entry.dwOwningPid,
                    conn_entry.dwLocalAddr,   # IP address as integer
                    conn_entry.dwRemoteAddr,  # IP address as integer
                    conn_entry.dwState       # Connection state (e.g., 2=LISTEN, 5=ESTABLISHED)
                ))

            return connections

        except Exception as e:
            print(f"Exception getting connections list: {e}")
            return None


    def protect_net_thread(self): # Network connection monitoring thread
        """Monitors for new network connections and checks against blocklists."""
        print("Network protection thread started.")
        while self.config_json.get("net_protect", 0) == 1:
            try:
                time.sleep(1) # Check interval (less frequent than process?)
                current_connections = self.get_connections_list()
                if current_connections is None: continue # Skip if error getting list

                # Find newly established or changed connections
                new_conns = current_connections - self.exist_connections

                if new_conns:
                    # print(f"New network connections/changes detected: {len(new_conns)}")
                    for conn_key in new_conns:
                        # conn_key = (PID, LocalAddr, RemoteAddr, State)
                        # We are interested in outgoing connections primarily (ESTABLISHED state?)
                        # State 5 = ESTABLISHED
                        if conn_key[3] == 5: # Check if connection is established
                             self.handle_new_connection(conn_key)

                # Update the known connection set
                self.exist_connections = current_connections

            except Exception as e:
                print(f"Error in network protection thread: {e}")
                time.sleep(5) # Wait longer after an error
        print("Network protection thread stopped.")


    def handle_new_connection(self, conn_key): # Check a new network connection
        """Checks the process and remote IP of a new connection against rules/blocklists."""
        pid, local_addr_int, remote_addr_int, state = conn_key
        h_process = None # Ensure defined

        # Ignore loopback connections (Remote IP 127.0.0.1 = 0x0100007F)
        if remote_addr_int == 0x0100007F:
            return

        # Convert remote IP integer to string format for easier checking
        # IP is stored in network byte order (reversed)
        remote_ip_str = f"{remote_addr_int & 0xFF}.{(remote_addr_int >> 8) & 0xFF}.{(remote_addr_int >> 16) & 0xFF}.{(remote_addr_int >> 24) & 0xFF}"

        try:
            # --- Open Process Handle ---
            # Need Query Info permission to get path
            access_flags = 0x1000 | 0x0400 | 0x0001 # Query Info + Terminate
            h_process = self.kernel32.OpenProcess(access_flags, False, pid)
            if not h_process: return # Cannot check process path or terminate

            # --- Get Process Path ---
            file_path = self.get_process_file(h_process)
            if not file_path or not os.path.exists(file_path):
                self.kernel32.CloseHandle(h_process)
                return

            file_path = file_path.replace("\\", "/")

            # --- Whitelist Check (Process) ---
            if self.check_whitelist(file_path):
                self.kernel32.CloseHandle(h_process)
                return

            # --- Blocklist Check (Remote IP) ---
            # Check against known malicious IPs (e.g., from YARA rules or another list)
            # Assuming self.rules.network is a set or list of blocked IP strings
            blocked_ips = getattr(self.rules, 'network', set()) # Get blocked IPs from rules engine
            if remote_ip_str in blocked_ips:
                 print(f"Blocked network connection: {file_path} (PID: {pid}) -> {remote_ip_str}")
                 # Kill the process making the blocked connection
                 self.kill_process(f"Blocked Network Connection ({remote_ip_str})", pid, file_path)
                 # Handle is closed by kill_process
                 h_process = None # Mark handle as closed
            # else: Connection is allowed

            # Close handle if not already closed by kill_process
            if h_process:
                self.kernel32.CloseHandle(h_process)

        except Exception as e:
            print(f"Error handling new connection for PID {pid} to {remote_ip_str}: {e}")
            if h_process: # Ensure handle is closed on error
                 try: self.kernel32.CloseHandle(h_process)
                 except: pass


# --- Main Execution Block ---
if __name__ == '__main__': # Check if script is run directly
    # Enable High DPI scaling for better visuals on high-resolution displays
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    # Policy for handling non-integer scale factors (PassThrough recommended for Qt 5.14+)
    QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    # Create the QApplication instance
    app = QApplication(sys.argv)

    # Create and initialize the main window controller
    # The window will show itself during init_config_done()
    main_window = MainWindow_Controller()

    # Start the Qt event loop
    sys.exit(app.exec_())
