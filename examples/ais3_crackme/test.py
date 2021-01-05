import angr

b = angr.Project('./test.exe', load_options={'auto_load_libs': False})

cfg = b.analyses.CFGEmulated(keep_state=True)
addr = 0x411780
# print(cfg.graph)
# print(len(cfg.graph.nodes()), len(cfg.graph.edges()))
#
# entry_node = cfg.get_any_node(addr)
#
# print('contexts :', len(cfg.get_all_nodes(addr)))
#
# print(entry_node.predecessors)
# print(entry_node.successors)


# print [jumpkind + ' to ' +hex(node.addr) for node , jumpkind in cfg.get_successors_and_jumpkind(entry_node)]

entry_func = cfg.kb.functions[addr]
# print entry_func.block_addrs
# func_graph = entry_func.transition_graph
# print func_graph
# print entry_func.returning
function = entry_func.callable
# p = []
out = function("ysg", 3)
print(out)
print(out.args[0])
