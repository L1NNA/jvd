import argparse
import platform
import subprocess

from jvd.normalizer.syntax import arm, mc68, metapc, ppc, tms320c6
from jvd.utils import read_gz_js

from jvd.ida.ida import IDA, ida_available
from jvd.ghidra import Ghidra


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
        return IDA()
    if disassembler == 'ghidra':
        return Ghidra()
    else:
        return None
