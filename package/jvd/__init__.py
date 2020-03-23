from jvd.normalizer.syntax import metapc, ppc, arm, mc68, tms320c6

def get_disassembler(use_ida=True):
    if use_ida:
        from jvd.ida.ida import IDA
        return IDA()
    else:
        from jvd.ghidra.decompiler import Ghidra
        return Ghidra()
