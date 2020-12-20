import argparse
import platform
import subprocess

import jvd.utils as jvdu
from jvd.normalizer.syntax import arm, mc68, metapc, ppc, tms320c6
from jvd.utils import read_gz_js


def set_home(new_home_path):
    jvdu.home = new_home_path


def get_disassembler(disassembler=None):
    """
    lazy import (so we can still change global path)
    """
    if disassembler is None:
        if ida_available:
            disassembler = 'ida'
        else:
            disassembler = 'ghidra'
    
    if disassembler == 'ida':
        from jvd.ida.ida import IDA
        return IDA()
    if disassembler == 'ghidra':
        from jvd.ghidra.decompiler import Ghidra
        return Ghidra()
    else:
        return None

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
