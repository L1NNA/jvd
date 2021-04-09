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
from jvd.unpackers import unpack_sample
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


def _process_single(s, capa=False, decompile=False,
                    clean_up=False, disassembler=None, unpack=True,
                    disassemble=True, inplace=True, verbose=-1):
    if isinstance(s, str):
        s = JVSample(s)
        s.save()
    if not unpack:
        samples = [s]
    else:
        samples = unpack_sample(s, inplace=inplace)
        for v in samples:
            label(v)
    dis = get_disassembler(disassembler)
    if disassemble:
        for v in samples:
            v: JVSample
            dis.disassemble(
                v.file, decompile=decompile, cleanup=clean_up,
                file_type=v.file_type,
                capa=capa, verbose=verbose,
            )
    return samples


def process_folder(
        folder, capa=False, decompile=False,
        clean_up=False, ext=None, disassembler=None, disassemble=True,
        unpack=True,
        verbose=-1):
    print('scanning files...')
    if os.path.isfile(folder):
        files = [folder]
    else:
        files = grep_ext(folder, ext=ext)
    # print('scanning files and tagging file information')
    # samples = [JVSample(f) for f in tqdm(files)]
    # for s in tqdm(samples):
    #     s.save()
    if len(files) > 0:
        # call first time to update any necessary resource
        s = JVSample(files[0])
        s.save()
        label(s)

    for _, result in m_map(
        partial(_process_single,
                capa=capa, decompile=decompile,
                clean_up=clean_up, disassembler=disassembler,
                verbose=verbose, disassemble=disassemble,
                unpack=unpack,
                ), files):
        pass
    print('done!')
