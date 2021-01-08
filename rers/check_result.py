def parse_csv(path):
    reachable = set()
    unreachable = set()

    with open(path, 'r') as file:
        while (line := file.readline()) and line is not None:
            #print('line', line)
            try:
                state, is_reachable = line.strip().split(',')
                is_reachable = is_reachable.strip()
                state = state.strip()
            except ValueError:
                line = line.strip('\n')
                state, is_reachable = line.strip().split('\t')

            if is_reachable == "true":
                reachable.add(int(state))
            else:
                unreachable.add(int(state))

    return reachable, unreachable