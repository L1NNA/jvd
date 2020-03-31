from jvd.normalizer.syntax import metapc, ppc, arm, mc68, tms320c6
import platform
import argparse
import subprocess

def get_disassembler(use_ida=True):
    if use_ida:
        from jvd.ida.ida import IDA
        return IDA()
    else:
        from jvd.ghidra.decompiler import Ghidra
        return Ghidra()

def which(program):
    import os

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


ida_available = which('ida64.exe' if platform.system() == 'Windows' else 'ida64') != None
