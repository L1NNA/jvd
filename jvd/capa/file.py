# if we have SMDA we also have
import struct

import capa.features.extractors.helpers as helpers
import capa.features.extractors.strings as strings
from capa.features import String, Characteristic
from capa.features.file import Export, Import, Section
from jvd.capa.data import DataUnit
from collections import defaultdict


def carve(pbytes, offset=0):
    '''
    Return a list of (offset, size, xor) tuples of embedded PEs

    Based on the version from vivisect:
    https://github.com/vivisect/vivisect/blob/7be4037b1cecc4551b397f840405a1fc606f9b53/PE/carve.py#L19
    And its IDA adaptation:
    capa/features/extractors/ida/file.py
    '''
    mz_xor = [
        (
            helpers.xor_static(b"MZ", i),
            helpers.xor_static(b"PE", i),
            i,
        )
        for i in range(256)
    ]

    pblen = len(pbytes)
    todo = [(pbytes.find(mzx, offset), mzx, pex, i) for mzx, pex, i in mz_xor]
    todo = [(off, mzx, pex, i) for (off, mzx, pex, i) in todo if off != -1]

    while len(todo):

        off, mzx, pex, i = todo.pop()

        # The MZ header has one field we will check
        # e_lfanew is at 0x3c
        e_lfanew = off + 0x3c
        if pblen < (e_lfanew + 4):
            continue

        newoff = struct.unpack('<I', helpers.xor_static(
            pbytes[e_lfanew: e_lfanew + 4], i))[0]

        nextres = pbytes.find(mzx, off+1)
        if nextres != -1:
            todo.append((nextres, mzx, pex, i))

        peoff = off + newoff
        if pblen < (peoff + 2):
            continue

        if pbytes[peoff: peoff + 2] == pex:
            yield (off, i)


def extract_file_embedded_pe(data: DataUnit):
    for offset, i in carve(data.fbytes, 1):
        yield Characteristic("embedded pe"), offset


def extract_file_export_names(data: DataUnit):
    for addr, name in data.obj.bin.export_functions.items():
        yield Export(name), addr


def extract_file_import_names(data: DataUnit):

    def gen():
        for addr, (module, f_name, _ord) in data.obj.bin.import_functions.items():
            if module.endswith('.dll'):
                module = module[:-4]
            if f_name:
                for symbol in helpers.generate_symbols(module, f_name):
                    yield Import(symbol), addr
            if _ord:
                _ord = str(_ord)
                f_name = "#{}".format(_ord)
                for symbol in helpers.generate_symbols(module, f_name):
                    yield Import(symbol), addr

    if not data.import_names:
        data.import_names = defaultdict(list)
        for i, a in gen():
            data.import_names[a].append(i)
    for addr, entries in data.import_names.items():
        for e in entries:
            yield e, addr


def extract_file_section_names(data: DataUnit):
    for addr, seg in data.obj.bin.seg.items():
        yield Section(seg), addr


def extract_file_strings(data: DataUnit):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    # for addr, s in data.obj.items():
    #     yield String(s), addr
    for s in strings.extract_ascii_strings(data.fbytes):
        yield String(s.s), s.offset

    for s in strings.extract_unicode_strings(data.fbytes):
        yield String(s.s), s.offset


def extract_features(data: DataUnit):
    """
    extract file features from given workspace

    args:
      smda_report (smda.common.SmdaReport): a SmdaReport
      file_path: path to the input file

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(data):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,


)
