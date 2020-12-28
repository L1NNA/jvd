from capa.features import Characteristic
from capa.features.extractors import loops
from jvd.capa.data import DataUnit


def extract_function_calls(f):
    unit: DataUnit = f.unit
    # print(f.calls)
    # print([f.addr_start for f in unit.map_f_xcall[f.addr_start]])
    for callee in f.calls:
        if f.addr_start == callee:
            continue
        if callee in unit.map_f :
            yield Characteristic("calls from"), unit.map_f[callee].addr_start
        else:
            yield Characteristic("calls from"), callee
    for caller in unit.map_f_xcall[f.addr_start]:
        if caller.addr_start in unit.map_f:
            yield Characteristic("calls to"), caller.addr_start
        else:
            print('what?')


def extract_function_loop(f):
    edges = []

    # construct control flow graph
    for b in f.blocks:
        for c in b.calls:
            edges.append((b.addr_start, c))

    if loops.has_loop(edges):
        yield Characteristic("loop"), f.addr_start


def extract_recursive_call(f):
    if f.addr_start in f.calls:
        yield Characteristic("recursive call"), f.addr_start


def extract_features(f):
    """extract function features

    arg:
        f (IDA func_t)
    """
    for func_handler in FUNCTION_HANDLERS:
        for (feature, ea) in func_handler(f):
            yield feature, ea


FUNCTION_HANDLERS = (extract_function_calls,
                     extract_function_loop, extract_recursive_call)
