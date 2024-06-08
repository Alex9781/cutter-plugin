import ctypes
import pefile
import os

working_directory = os.getenv("APPDATA", "null") + "\\rizin\\cutter\\plugins\\python\\cutter-plugin\\" 

def convert(path: str, offset: int):
    pe2dll=pefile.PE(path, fast_load=True)

    pe2dll.FILE_HEADER.Characteristics=0x2022 # type: ignore
    rvaEntry = pe2dll.OPTIONAL_HEADER.AddressOfEntryPoint # type: ignore

    textsection = filter(lambda x: b'.text' in x.Name, pe2dll.sections)
    textsection = list(textsection)

    textVA = textsection[0].VirtualAddress
    textRaw = textsection[0].PointerToRawData

    # print(pe2dll.get_offset_from_rva(rvaEntry))   
    rawEntry = rvaEntry - textVA + textRaw
    #print(rawEntry)

    pe2dll.write(filename=working_directory + "converted.dll")


    with open(working_directory + "converted.dll", "r+b") as dllFile:
        dllFile.seek(rawEntry)
        dllFile.write(bytes.fromhex('b801000000c3'))


    lib = ctypes.cdll.LoadLibrary(working_directory + "converted.dll")

    # print("---------------------------")
    # print(hex(ctypes.cast(lib._handle, ctypes.c_void_p).value + offset))

    return ctypes.cast(lib._handle, ctypes.c_void_p).value + offset  # type: ignore

    #print(hex(ctypes.cast(lib._handle, ctypes.c_void_p).value))

