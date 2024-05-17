import ctypes
import pefile
import os, sys

# import shutil
# shutil.copyfile("ConsoleApplication1.exe", "ConsoleApplication1.dll")

pe2dll=pefile.PE("ConsoleApplication1.exe", fast_load=True)
print(hex(pe2dll.FILE_HEADER.Characteristics))
pe2dll.FILE_HEADER.Characteristics=0x20
rvaEntry = pe2dll.OPTIONAL_HEADER.AddressOfEntryPoint
# for i in pe2dll.sections:
#     print(i)
textsection = filter(lambda x: b'.text' in x.Name, pe2dll.sections)
textsection = list(textsection)
# print(f"textsection = {list(textsection)[0]}")
textVA = textsection[0].VirtualAddress
textRaw = textsection[0].PointerToRawData

# print(pe2dll.get_offset_from_rva(rvaEntry))
rawEntry = rvaEntry - textVA + textRaw
print(rawEntry)

pe2dll.write(filename="ConsoleApplication1.dll")


with open("ConsoleApplication1.dll", "r+b") as dllFile:
    dllFile.seek(rawEntry)
    dllFile.write(bytes.fromhex('b801000000c20c00'))


#КОНСТАНТА СМЕЩЕНИЯ ФУКНЦИИ - ИЗ ДИЗАССЕМБЛЕРА


lib = ctypes.cdll.LoadLibrary("ConsoleApplication1.dll")
print(hex(ctypes.cast(lib._handle, ctypes.c_void_p).value))

#КОНСТАНТА СМЕЩЕНИЯ ФУКНЦИИ - ИЗ ДИЗАССЕМБЛЕРА

