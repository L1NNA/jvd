import sys
import test.test_capa.tests.fixtures as fixtures
from test.test_capa.tests.fixtures import *
from functools import lru_cache
from jvd import get_disassembler
from jvd.capa import capa_analyze
from jvd.disassembler import DisassemblerAbstract
from jvd.utils import read_gz_js
from jvd import ida_available


def test_jvd_field_missing():

    bin = os.path.join('test', 'test_jvd', 'libpng-1.7.0b54.o')
    disassembler = get_disassembler('ghidra')
    disassembler: DisassemblerAbstract
    gz_obj, logs = disassembler.disassemble(
        bin, cleanup=False, capa=True, decompile=True,)
    print(logs)
    assert 'capa' in gz_obj
    cap = gz_obj['capa']
    assert len(cap['tac']) > 0
    assert len(cap['mbc']) > 0
    assert len(cap['cap']) > 0
    assert len(gz_obj['functions_src']) > 10

    with xfail(not ida_available, reason="IDA is not available"):
        bin = os.path.join('test', 'test_jvd', 'zlib-1.2.7.o')
        disassembler = get_disassembler('ida')
        disassembler: DisassemblerAbstract
        gz_obj, logs = disassembler.disassemble(
            bin, cleanup=False, capa=True, decompile=True,)
        print(logs)
        assert 'capa' in gz_obj
        cap = gz_obj['capa']
        assert len(cap['tac']) > 1
        assert len(cap['mbc']) > 1
        assert len(cap['cap']) > 1
        assert len(gz_obj['functions_src']) > 10
