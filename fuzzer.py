import ctypes
import pyqbdi
import sys
import struct
import atexit
import random

###

class CovModule:
    # Create the full range memory for all module

    def __init__(self, module):
        self.name = module.name
        self.range = pyqbdi.Range(module.range.start, module.range.end)
        self.executable = module.permission & pyqbdi.PF_EXEC

    def append(self, module):
        assert module.name == self.name
        if module.range.start < self.range.start:
            self.range.start = module.range.start
        if self.range.end < module.range.end:
            self.range.end = module.range.end
        self.executable |= module.permission & pyqbdi.PF_EXEC

def get_modules():
    _modules = {}
    for m in pyqbdi.getCurrentProcessMaps(True):
        if m.name in _modules:
            _modules[m.name].append(m)
        elif '\\' in m.name:
            _modules[m.name] = CovModule(m)

    _modules = {k: v for k, v in _modules.items() if v.executable}

    modules = []
    for (_, m) in _modules.items():
        for n in modules:
            assert not m.range.overlaps(n.range), "Error when try to identify module range"
        modules.append(m)

    return modules


# write coverage (in drcov format)
def writeCoverage(stats):
    filename = "C:\\Users\\alexz\\AppData\\Roaming\\rizin\\cutter\\plugins\\python\\cutter-plugin\\a.cov"
    with open(filename, "w", newline='') as fp:
        # write header
        fp.write("DRCOV VERSION: 3\n")
        fp.write("DRCOV FLAVOR: drcov\n")
        modules = get_modules()
        fp.write("Module Table: version 2, count %u\n" % len(modules))
        fp.write("Columns: id, base, end, entry, path\n")
        # write modules
        fmt = "%2u, 0x%x, 0x%x, 0x0000000000000000, %s\n"
        for mid, m in enumerate(modules):
            fp.write(fmt % (mid, m.range[0], m.range[1], m.name))
        addrs = stats["addrs"]
        sizes = stats["sizes"]
        # find address offsets from their module base
        starts = {}
        for addr in addrs:
            for mid, m in enumerate(modules):
                if addr >= m.range[0] and addr < m.range[1]:
                    starts[addr] = (mid, addr - m.range[0])
                    break
        # write basicblocks
        fp.write("BB Table: %u bbs\n" % len(starts))

    with open(filename, "ab") as fp:
        for addr, (mid, start) in starts.items():
            # uint32_t start; uint16_t size; uint16_t id;
            bb = struct.pack("<IHH", start, sizes[addr], mid)
            fp.write(bb)


def vmCB(vm, evt, gpr, fpr, data):
    if evt.event & pyqbdi.BASIC_BLOCK_ENTRY:
        addr = evt.basicBlockStart
        size = evt.basicBlockEnd - addr
        data["addrs"].add(addr)
        data["sizes"][addr] = size
    return pyqbdi.CONTINUE

def pyqbdipreload_on_run(vm, start, stop):

    # setup statistics
    stats = dict(addrs=set(), sizes=dict())
    # add callback on Basic blocks
    vm.addVMEventCB(pyqbdi.BASIC_BLOCK_ENTRY, vmCB, stats)
    # write coverage on exit
    atexit.register(writeCoverage, stats)
    # run program
    vm.run(start, stop)

    return stats
###

def insnCB(vm, gpr, fpr, data):
    instAnalysis = vm.getInstAnalysis()
    #print("0x{:x}: {}".format(instAnalysis.address, instAnalysis.disassembly))
    return pyqbdi.CONTINUE

lib_path = sys.argv[1]
func_name = sys.argv[2]

# lib_path = "C:\\Users\\alexz\\Desktop\\Dll1\\x64\\Release\\Dll1.dll"
# func_name = "test_func3"

lib = ctypes.cdll.LoadLibrary(lib_path)
funcPtr = ctypes.cast(lib[func_name], ctypes.c_void_p).value

vm = pyqbdi.VM()

state = vm.getGPRState()
addr = pyqbdi.allocateVirtualStack(state, 0x100000)
assert addr is not None

vm.addInstrumentedModuleFromAddr(funcPtr)
vm.recordMemoryAccess(pyqbdi.MEMORY_READ_WRITE)

vm.addCodeCB(pyqbdi.PREINST, insnCB, None)

# # Cast double arg to long and set FPR
# fpr = vm.getFPRState() 
#carg = struct.pack('<I', arg) # !!! https://docs.python.org/3/library/struct.html#format-characters
# fpr.xmm0 = 1.0


gpr = vm.getGPRState()
gpr.rcx = random.randint(0, 10)
gpr.rdx = struct.pack('<s', bytes("qweqwe", "utf-8"))

pyqbdi.simulateCall(state, 0x42424242)
stats = pyqbdipreload_on_run(vm, funcPtr, 0x42424242)

#success = vm.run(funcPtr, 0x42424242)

# # # Retrieve output FPR state
# # fpr = vm.getFPRState()
# # # Cast long arg to double
# # res = struct.unpack('<d', fpr.xmm0[:8])[0]
# # print("%f (python) vs %f (qbdi)" % (math.sin(arg), res))

pyqbdi.alignedFree(addr)

sys.exit(0)
