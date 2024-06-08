import cutter
import subprocess
import os

from PySide2.QtCore import QObject, SIGNAL # type: ignore
from PySide2.QtWidgets import QAction, QLabel, QPushButton # type: ignore

class MyDockWidget(cutter.CutterDockWidget): # type: ignore
    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("MyDockWidget")
        self.setWindowTitle("My cool DockWidget")

        self._label = QLabel(self)
        self.setWidget(self._label)

        QObject.connect(cutter.core(), SIGNAL("seekChanged(RVA)"), self.update_contents) # type: ignore
        self.update_contents()

    def update_contents(self):
        func_flag = cutter.cmd("afd") # type: ignore
        try:
            self.exec_fuzing(func_flag)
        except:
            pass
        self._label.setText(cutter.cmd("afd")) # type: ignore

    def exec_fuzing(self, flag: str):
        # флаг - это автоматической название функции присваемое Cutter'ом
        flag = flag.strip()

        exports = cutter.cmdj("iEj") # type: ignore
        file_path = cutter.cmdj("ij")["core"]["file"] # type: ignore

        func_name = ""
        for func in exports:
            if func['flagname'] == flag: func_name = func['realname']

        working_directory = os.getenv("APPDATA", "null") + "\\rizin\\cutter\\plugins\\python\\cutter-plugin\\"

        if func_name:
            res = subprocess.run(["python", working_directory + "fuzzer.py", "1", file_path, func_name, "0"], capture_output=True)
            print(res.stdout)
        else:
            # print(cutter.cmd("s")) #type: ignore
            # print(int(cutter.cmd("s"), 0)) #type: ignore

            print("############")

            offset = int(cutter.cmd("s"), 0) - 0x140000000 #type: ignore
            # print(hex(offset))
            res = subprocess.run(["python", working_directory + "fuzzer.py", "0", file_path, "null", str(offset)], capture_output=True)
            print(res)



class MyCutterPlugin(cutter.CutterPlugin): # type: ignore
    name = "My Plugin"
    description = "Plugin for extracting functions arguments"
    version = "1.0"
    author = "Unidentified Squirrel"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("My Plugin", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    return MyCutterPlugin()
