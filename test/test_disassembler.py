import os
from jvd import get_disassembler
from jvd.disassembler import DisassemblerAbstract
from jvd.utils import read_gz_js
from jvd import ida_available
from test.test_capa.tests.fixtures import xfail
import os
from contextlib import contextmanager
import traceback


def get_testing_binary(binary_name):
    selected = os.path.join('test', 'test_jvd', binary_name)
    assert os.path.exists(selected)
    return selected


@contextmanager
def helper_function(disassembler, capa, decompile, binary='libpng-1.7.0b54.o'):
    gz_file = None
    try:
        binary = get_testing_binary(binary)
        disassembler = get_disassembler(disassembler)
        disassembler: DisassemblerAbstract
        gz_file, logs = disassembler.disassemble(
            binary, cleanup=False, capa=capa, decompile=decompile, verbose=2)
        gz_obj = read_gz_js(gz_file)
        yield gz_obj
    except:
        print(traceback.format_exc())
    finally:
        if gz_file is not None and os.path.exists(gz_file):
            os.remove(gz_file)


def test_ghidra_disassemble():

    with helper_function('ghidra', False, False) as gz_obj:
        assert len(gz_obj['functions']) > 10


def test_ghidra_decompile():

    with helper_function('ghidra', False, True) as gz_obj:
        assert len(gz_obj['functions']) > 10
        assert len(gz_obj['functions_src']) > 10


def test_ghidra_capa():

    with helper_function('ghidra', True, False) as gz_obj:
        assert len(gz_obj['functions']) > 10
        assert len(gz_obj['capa']) > 5


def test_ida_disassemble():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida', False, False) as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_disassemble_idb32():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida', False, False, binary='busybox-i686.idb') as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_disassemble_idb64():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida', False, False, binary='busybox-x86_64.i64') as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_decompile():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida', False, True) as gz_obj:
            assert len(gz_obj['functions']) > 10
            assert len(gz_obj['functions_src']) > 10


def test_ida_capa():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida', True, False) as gz_obj:
            assert len(gz_obj['functions']) > 10
            assert len(gz_obj['capa']) > 5
