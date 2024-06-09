import cutter
import subprocess
import os

inCutter = True
if inCutter:
    from PySide2.QtCore import QObject, SIGNAL # type: ignore
    from PySide2.QtWidgets import (QAction, QLabel, QPushButton, QWidget, # type: ignore
                                   QMessageBox, QGridLayout, QSpacerItem, QSizePolicy, # type: ignore
                                   QLineEdit, QPlainTextEdit) # type: ignore
else:
    from PySide6.QtCore import QObject, SIGNAL # type: ignore
    from PySide6.QtWidgets import (QAction, QLabel, QPushButton, QWidget, # type: ignore
                                   QMessageBox, QGridLayout, QSpacerItem, QSizePolicy, # type: ignore
                                   QLineEdit, QPlainTextEdit) # type: ignore
 
class MyDockWidget(cutter.CutterDockWidget): # type: ignore
    """
    Вкладка, появляющаяся в Cutter при загрузке плагина
    """
    _lyt : QGridLayout

    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("FuzzingWidget")
        self.setWindowTitle("Фаззинг")

        self._wgt = QWidget(self)
        self.setWidget(self._wgt)
        self.setupGUI()
        # по изменению текущей функции
        # QObject.connect(
        #     cutter.core(),
        #     SIGNAL("seekChanged(RVA)"), # сигнал Cutter, https://cutter.re/docs/api/core/classCutterCore.html#_CPPv4N10CutterCore11seekChangedE3RVA15SeekHistoryType
        #     self.update_contents) # type: ignore
        # self.update_contents()

    def setupGUI(self:QWidget):
        self._lyt = QGridLayout(parent=self._wgt)

        self._btnStartRandomFuzzing = QPushButton(text="Случайный\nфаззинг")
        self._btnStartRandomFuzzing.clicked.connect(self.exec_fuzing)
        self._lyt.addWidget(self._btnStartRandomFuzzing)

        self._btnStartAngr = QPushButton(text="SMT")
        self._btnStartAngr.clicked.connect(lambda _: self.start_smt(
            entry=self._entry.text(),
            find_addr=self._findInput.text(),
            avoid_addr=self._avoidInput.text(),
            arguments=self._arguments.text(),
            num_find=self._num_find.text()
        ))
        self._lyt.addWidget(self._btnStartAngr)


        self._entry = QLineEdit("0x140001000")
        self._entry.setPlaceholderText("Точка входа")
        self._lyt.addWidget(self._entry)

        self._findInput = QLineEdit("0x140001048")
        self._findInput.setPlaceholderText("Целевые адреса, разделить запятой")
        self._lyt.addWidget(self._findInput)

        self._avoidInput = QLineEdit("0x140001013, 0x14000105d")
        self._avoidInput.setPlaceholderText("Запрещённые адреса, разделить запятой")
        self._lyt.addWidget(self._avoidInput)

        self._arguments = QLineEdit("edx, ecx")
        self._arguments.setPlaceholderText("Переменные")
        self._lyt.addWidget(self._arguments)

        self._num_find = QLineEdit("3")
        self._num_find.setPlaceholderText("Количество решений")
        self._lyt.addWidget(self._num_find)

        self._output = QPlainTextEdit()
        self._output.setPlaceholderText("Вывод решателя")
        self._lyt.addWidget(self._output)

        self._lyt.addItem(QSpacerItem(40, 40, hData=QSizePolicy.Policy.Expanding, vData=QSizePolicy.Policy.Expanding))#, row=1, column=1)
        self._wgt.setLayout(self._lyt)
        return

    def start_smt(self:QWidget, entry: str, find_addr: str, avoid_addr: str, arguments: str, num_find: str):
        """
        Вызов ANGR в подпроцессе
        Args:
            
        """
        file_path = cutter.cmdj("ij")["core"]["file"] # type: ignore

        working_directory = os.getenv("APPDATA", "null") + "\\rizin\\cutter\\plugins\\python\\cutter-plugin\\"

        """
        1 путь к модулю
        2 точка входа = "0x..."
        3 find = "[0x..., 0x...]"
        4 avoid = "[0x..., 0x...]"
        5 arguments = "[eax, rsi, 0x....]"
        6 num_find = 
        """
        self._output.clear()
        res = subprocess.run(["python", working_directory + "smtsolver.py",
                              file_path, entry, find_addr, avoid_addr, arguments, num_find],
                              capture_output=True)
        self._output.appendPlainText(res.stdout.decode("utf-8"))


    def exec_fuzing(self):
        """
        Сам фаззинг
        """
        # флаг - это автоматической название функции присваемое Cutter'ом
        flag = cutter.cmd("afd").strip() # type: ignore

        print(flag)

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
    """
    Служебный код для инициализации плагина в Cutter

    Args:
        cutter (_type_): _description_
    """
    name = "FuzzingPlugin"
    description = "Plugin for function fuzzing and SMT-extracting functions arguments"
    version = "1.1"
    author = "Unidentified Squirrel, Ornstein89"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("FuzzingPlugin", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    return MyCutterPlugin()
