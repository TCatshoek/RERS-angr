import angr
import re
from tqdm import tqdm
import claripy

# Define which rers problem we are solving
problem = "Problem11"
problemset = "TrainingSeqReachRers2019"

proj = angr.Project(f'rers/{problemset}/{problem}/{problem}')

# Restrict input
input_len = 8

# We create a bitvector representing stdin
input_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
sym_input = claripy.Concat( *input_chars )

# Setup the initial state, and point it to the symbolic input
state = proj.factory.entry_state(stdin=sym_input)
simgr = proj.factory.simgr(state)

# Add constraints on input bytes, we know the valid inputs (look at the rers code)
for k in input_chars:
    state.solver.add(k >= 0x01)
    state.solver.add(k <= 0x10)

# Explore for a few iterations
# Explore runs until a new state is found that satisfies the "find" condition,
# e.g. stderr contains the string "error"
n_iterations = 1

for i in tqdm(range(n_iterations)):

    simgr.explore(
        find=lambda s: b"error" in s.posix.dumps(2),
        avoid=lambda s: b"Invalid" in s.posix.dumps(2),
    )

    print("ACTIVE")
    for a in simgr.active:
        print(a.posix.dumps(0), a.posix.dumps(1), a.posix.dumps(2))

    print("FOUND")
    for a in simgr.found:
        print(a.posix.dumps(0), a.posix.dumps(1), a.posix.dumps(2))

    print("AVOID")
    for a in simgr.avoid:
        print(a.posix.dumps(0), a.posix.dumps(1), a.posix.dumps(2))

# Decode the results
result = set([a.posix.dumps(2).decode() for a in simgr.found])
reached = set([int(re.search('[0-9]+', r).group(0)) for r in result])

# And check how well we did on the RERS problems
from rers.check_result import parse_csv
reachable, unreachable = parse_csv(f'rers/{problemset}/{problem}/reachability-solution-{problem}.csv')

print("\nRESULTS:")
print(f"Reached {len(reached)}/{len(reachable)} errors")

if len(reachable.difference(reached)) > 0:
    print("Not reached", reachable - reached)
    print("Falsely reached", reached - reachable)
else:
    print("Success")