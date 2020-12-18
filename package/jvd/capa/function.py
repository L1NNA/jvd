from capa.features import Characteristic
from capa.features.extractors import loops


def extract_function_calls_to(f):
    for ea in f.xref:
        yield Characteristic("calls to"), ea


def extract_function_loop(f):
    edges = []

    # construct control flow graph
    for b in f.blocks:
        for c in b.calls:
            edges.append((b._id, c))

    if loops.has_loop(edges):
        yield Characteristic("loop"), f.addr_start


def extract_recursive_call(f):
    if f._id in f.calls:
        yield Characteristic("recursive call"), f.addr_start


def extract_features(f):
    """extract function features

    arg:
        f (IDA func_t)
    """
    for func_handler in FUNCTION_HANDLERS:
        for (feature, ea) in func_handler(f):
            yield feature, ea


FUNCTION_HANDLERS = (extract_function_calls_to,
                     extract_function_loop, extract_recursive_call)
