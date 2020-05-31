#!/usr/local/bin/python3
import argparse
import os

from octopus.arch.wasm.cfg import WasmCFG, CFGGraph
from graphviz import Digraph

DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_FILE = DIR + "/data/opt.wasm"

OUT_INSN = "insn"
OUT_FLOW = "flow"

_groups = {0x00: 'Control',
           0x1A: 'Parametric',
           0x20: 'Variable',
           0x28: 'Memory',
           0x41: 'Constant',
           0x45: 'Logical_i32',
           0x50: 'Logical_i64',
           0x5b: 'Logical_f32',
           0x61: 'Logical_f64',
           0x67: 'Arithmetic_i32',
           0x71: 'Bitwise_i32',
           0x79: 'Arithmetic_i64',
           0x83: 'Bitwise_i64',
           0x8b: 'Arithmetic_f32',
           0x99: 'Arithmetic_f64',
           0xa7: 'Conversion'}

DESIGN_IMPORT = {'fillcolor': 'turquoise',
                 'shape': 'box',
                 'style': 'filled'}

DESIGN_EXPORT = {'fillcolor': 'grey',
                 'shape': 'box',
                 'style': 'filled'}

DESIGN_MARKED = {'fillcolor': 'red'}

def visualize_insns(functions, show=True, save=True,
                    out_filename=OUT_INSN,
                    fontsize=8):
    import numpy as np
    import matplotlib.pyplot as plt

    final = list()
    datas = list()

    # legend x axis - name functions
    group_names = tuple([func.name for func in functions])
    # number of functions
    ind = [x for x, _ in enumerate(functions)]

    # list all groups
    all_groups = [v for _, v in _groups.items()]

    # list()
    for func in functions:
        data = list()
        group = [i.group for i in func.instructions]
        for g in all_groups:
            data.append(group.count(g))
        datas.append(tuple(data))

    for idx in range(len(all_groups)):
        final.append(tuple([x[idx] for x in datas]))

    # choice color: https://matplotlib.org/users/colormaps.html
    color = iter(plt.cm.gist_rainbow(np.linspace(0, 1, len(all_groups))))
    stack = np.array([0 * len(all_groups)])
    for idx in range(len(all_groups)):
        if idx == 0:
            # first bar
            plt.barh(ind, final[idx], label=all_groups[idx],
                     align='center', color=next(color))
        else:
            plt.barh(ind, final[idx], label=all_groups[idx], left=stack,
                     align='center', color=next(color))

        stack = stack + np.array(final[idx])

    # Rotate x-labels on the x-axis
    plt.yticks(fontsize=fontsize)
    plt.ylim([0, len(functions)])
    plt.yticks(ind, group_names)
    plt.ylabel('Functions')
    plt.xlabel('Instructions count')
    plt.legend(loc="lower right")
    plt.title('Instructions count by function and group')

    # save
    if save:
        plt.savefig(out_filename)
    # show
    if show:
        plt.show()

def enum_func_name_call_indirect(functions):
    ''' return a list of function name if they used call_indirect
    '''
    func_name = list()

    # iterate over functions
    for func in functions:
        for inst in func.instructions:
            if inst.name == "call_indirect":
                func_name.append(func.name)
    func_name = list(set(func_name))
    return func_name

def bfs(visited, graph, node):
  queue = []
  visited[node] = 1
  queue.append(node)

  while queue:
    s = queue.pop(0)
    for child in graph[s]:
      if child not in visited:
        visited[child] = 1
        queue.append(child)

def visualize_flow(cfg, filename=OUT_FLOW, marked={}, only_relevant=True):
        nodes, edges = cfg.get_functions_call_edges()

        g = Digraph(filename, filename=filename)
        g.attr(rankdir='LR')

        with g.subgraph(name='global') as c:

            export_list = [p[0] for p in cfg.analyzer.func_prototypes if p[3] == 'export']
            import_list = [p[0] for p in cfg.analyzer.func_prototypes if p[3] == 'import']
            call_indirect_list = enum_func_name_call_indirect(cfg.functions)

            only_show = {}
            if only_relevant:
                # Build transposed graph, and add all the nodes reachable from
                # the marked nodes to only_show. Also include all imports and exports.
                only_show = {}
                transposed_edges = {}
                for node in nodes:
                    transposed_edges[node] = []
                for edge in edges:
                    current = transposed_edges.get(edge.node_to)
                    current.append(edge.node_from)
                # Do BFS.
                for m in marked:
                    bfs(only_show, transposed_edges, m)
                for n in export_list: only_show[n] = 1
                for n in import_list: only_show[n] = 1

            try:
                indirect_target = [cfg.analyzer.func_prototypes[index][0] for index in cfg.analyzer.elements[0].get('elems')]
            except IndexError:
                indirect_target = []
            # create all the graph nodes (function name)
            for idx, node in enumerate(nodes):
                if only_relevant and not node in only_show:
                    continue

                # name graph bubble
                node_name = node
                # default style value
                fillcolor = "white"
                shape = "ellipse"
                style = "filled"
                label = None

                if node in marked:
                    label = node + "[" + str(marked[node]) + "]"

                if node in import_list:
                    fillcolor = DESIGN_IMPORT.get('fillcolor')
                    shape = DESIGN_IMPORT.get('shape')
                    style = DESIGN_IMPORT.get('style')
                    c.node(node_name, label=label, fillcolor=fillcolor, shape=shape, style=style)
                elif node in export_list:
                    fillcolor = DESIGN_EXPORT.get('fillcolor')
                    shape = DESIGN_EXPORT.get('shape')
                    style = DESIGN_EXPORT.get('style')
                    c.node(node_name, label=label, fillcolor=fillcolor, shape=shape, style=style)

                if node in marked:
                    fillcolor = DESIGN_MARKED.get('fillcolor')

                if node in indirect_target:
                    shape = "hexagon"

                if node in call_indirect_list:
                    style = "dashed"
                c.node(node_name, label=label, fillcolor=fillcolor, shape=shape, style=style)

            # check if multiple same edges
            # in that case, put the number into label
            edges_counter = dict((x, edges.count(x)) for x in set(edges))
            # insert edges on the graph
            for edge, count in edges_counter.items():
                label = None
                if count > 1:
                    label = str(count)
                if only_relevant:
                    if not (edge.node_from in only_show and edge.node_to in only_show):
                        continue
                c.edge(edge.node_from, edge.node_to, label=label)

        g.render(filename, view=True)

def process_file(file, count, do_insn, do_flow, full_flow):
    with open(file, 'rb') as f:
        module_bytecode = f.read()
    cfg = WasmCFG(module_bytecode)
    largest_functions = sorted(cfg.functions, key=lambda func: len(func.instructions), reverse=True)
    hogs = dict(map(lambda func: (func.name, len(func.instructions)), largest_functions[:count]))
    print(hogs)
    if do_insn:
        visualize_insns(largest_functions[:count])

    if do_flow:
        visualize_flow(cfg, marked=hogs, only_relevant=not full_flow)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--flow',
                        action='store_true',
                        default=True,
                        help='Show control flow between functions, largest marked red')
    parser.add_argument('--instructions',
                        action='store_true',
                        default=False,
                        help='Show instructions in largest functions')
    parser.add_argument('--count',
                        default=30,
                        help='How many biggest functions take into account')
    parser.add_argument('--full_graph',
                        action='store_true',
                        default=False,
                        help='Show full call graph, or only relevant part')
    parser.add_argument('--input',
                        default=DEFAULT_FILE,
                        help='WASM file to analyze')
    args = parser.parse_args()
    if args.instructions:
       args.flow = False
    process_file(args.input, int(args.count), args.instructions, args.flow, args.full_graph)
