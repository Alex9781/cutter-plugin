import angr
import sys

"""
1 путь к модулю
2 точка входа = "0x..."
3 find = "[0x..., 0x...]"
4 avoid = "[0x..., 0x...]"
5 arguments = "[eax, rsi, 0x....]"
6 num_find = 
"""

imagepath = sys.argv[1]
entrypoint = int(sys.argv[2], 0)
find_list  = [int(x.strip(),0) for x in sys.argv[3].split(',')]
avoid_list = [int(x.strip(),0) for x in sys.argv[4].split(',')]
# arguments
num_find = int(sys.argv[6])

project = angr.Project(imagepath, auto_load_libs=False)
state = project.factory.blank_state(addr = entrypoint)

#TODO разобрать 
a_bvs = state.solver.BVS(name='a', size=8*4)
b_bvs = state.solver.BVS(name='b', size=8*4)

state.regs.edx = a_bvs
state.regs.ecx = b_bvs
# state.memory.store(state.regs.rsp + 8, eax_bvs)
# state.regs.rdx = a

state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
simulationManager = project.factory.simulation_manager(state)

simulationManager.explore(
    find=find_list,
    avoid=avoid_list,
    num_find = 3,
    # step_func=lambda lsimulationManager: lsimulationManager.drop(stash='avoid')
)  # find a way through to the goodboy routine

for i, itm in enumerate(simulationManager.found):
    print(f"Solution {i}:")
    print(itm.solver.eval(a_bvs))
    print(itm.solver.eval(b_bvs))
    