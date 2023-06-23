import os
from jvd import get_disassembler
from jvd.disassembler import DisassemblerAbstract
from jvd.utils import read_gz_js
from jvd import ida_available
from test.test_capa.tests.fixtures import xfail
import os


def test_jvd_disassemblers():

    bin = os.path.join('test', 'test_jvd', 'libpng-1.7.0b54.o')
    disassembler = get_disassembler('ghidra')
    disassembler: DisassemblerAbstract
    gz_file, logs = disassembler.disassemble(
        bin, cleanup=False, capa=False, decompile=False, verbose=2)
    print(logs)
    gz_obj = read_gz_js(gz_file)
    assert len(gz_obj['functions']) > 10
    os.remove(gz_file)

    with xfail(not ida_available, reason="IDA is not available"):
        bin = os.path.join('tests', 'test_jvd', 'zlib-1.2.7.o')
        disassembler = get_disassembler('ida')
        disassembler: DisassemblerAbstract
        gz_file, logs = disassembler.disassemble(
            bin, cleanup=False, capa=False, decompile=False,)
        print(logs)
        gz_obj = read_gz_js(gz_file)
        assert len(gz_obj['functions']) > 0
