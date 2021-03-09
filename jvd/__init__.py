import argparse
import platform
import subprocess

from jvd.normalizer.syntax import arm, mc68, metapc, ppc, tms320c6
from jvd.utils import read_gz_js

from jvd.ida.ida import IDA, ida_available
from jvd.ghidra import Ghidra
from jvd.resources import require
import os
from pathlib import Path
from jvd.unpackers import unpack
from jvd.labelers import label
from jvd.utils import JVSample, grep_ext, m_map
from tqdm import tqdm
from functools import partial
import logging as log


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


def _process_single(s, cfg=False, capa=False, decompile=False,
                    clean_up=False, disassembler=None, verbose=-1):
    if not isinstance(s, JVSample):
        s = JVSample(s)
        s.save()
    samples = unpack(s)
    for v in samples:
        label(v)
    dis = get_disassembler(disassembler)
    for v in samples:
        v: JVSample
        dis.disassemble(
            v.file, decompile=decompile, cleanup=clean_up,
            cfg=cfg, no_result=True, file_type=v.file_type,
            capa=capa, verbose=verbose,
        )
    return samples


def process_folder(
        folder, cfg=False, capa=False, decompile=False,
        clean_up=False, ext=None, disassembler=None, verbose=-1):
    if os.path.isfile(folder):
        files = [folder]
    files = grep_ext(folder, ext=ext)
    samples = [JVSample(f) for f in files]

    for s in samples:
        s.save()
    if len(samples) > 0:
        # call first time to update any necessary resource
        label(samples[0])

    for _, result in m_map(
        partial(_process_single,
                cfg=cfg, capa=capa, decompile=decompile,
                clean_up=clean_up, disassembler=disassembler,
                verbose=verbose
                ), samples):
        pass
    print('done!')
    # label(s)
