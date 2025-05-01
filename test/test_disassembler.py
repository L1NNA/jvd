import os
from jvd import get_disassembler
from jvd.disassembler import DisassemblerAbstract
from jvd.utils import read_gz_js
from jvd import ida_available
import os
from contextlib import contextmanager
import traceback
import pytest
import contextlib


@contextlib.contextmanager
def xfail(condition, reason=None):
    """
    source: capa
    https://github.com/mandiant/capa/blob/9d3d3be21dda5d6a646dac38b645fd5a30a9aa52/tests/fixtures.py#L62
    context manager that wraps a block that is expected to fail in some cases.
    when it does fail (and is expected), then mark this as pytest.xfail.
    if its unexpected, raise an exception, so the test fails.

    example::

        # this test:
        #  - passes on Linux if foo() works
        #  - fails  on Linux if foo() fails
        #  - xfails on Windows if foo() fails
        #  - fails  on Windows if foo() works
        with xfail(sys.platform == "win32", reason="doesn't work on Windows"):
            foo()
    """
    try:
        # do the block
        yield
    except Exception:
        if condition:
            # we expected the test to fail, so raise and register this via pytest
            pytest.xfail(reason)
        else:
            # we don't expect an exception, so the test should fail
            raise
    else:
        if not condition:
            # here we expect the block to run successfully,
            # and we've received no exception,
            # so this is good
            pass
        else:
            # we expected an exception, but didn't find one. that's an error.
            raise RuntimeError("expected to fail, but didn't")


def get_testing_binary(binary_name):
    selected = os.path.join('test', 'test_jvd', binary_name)
    assert os.path.exists(selected)
    return selected


@contextmanager
def helper_function(disassembler, decompile, binary='libpng-1.7.0b54.o'):
    gz_file = None
    try:
        binary = get_testing_binary(binary)
        disassembler = get_disassembler(disassembler)
        disassembler: DisassemblerAbstract
        gz_file, logs = disassembler.disassemble(
            binary, cleanup=False,  decompile=decompile, verbose=2)
        gz_obj = read_gz_js(gz_file)
        yield gz_obj
    except:
        print(traceback.format_exc())
    finally:
        if gz_file is not None and os.path.exists(gz_file):
            os.remove(gz_file)


def test_ghidra_disassemble():

    with helper_function('ghidra', False) as gz_obj:
        assert len(gz_obj['functions']) > 10


def test_ghidra_decompile():

    with helper_function('ghidra',   True) as gz_obj:
        assert len(gz_obj['functions']) > 10
        assert len(gz_obj['functions_src']) > 10



def test_ida_disassemble():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida',  False) as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_disassemble_idb32():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida',  False, binary='busybox-i686.idb') as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_disassemble_idb64():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida',  False, binary='busybox-x86_64.i64') as gz_obj:
            assert len(gz_obj['functions']) > 10


def test_ida_decompile():

    with xfail(not ida_available, reason="IDA is not available"):
        with helper_function('ida',  True) as gz_obj:
            assert len(gz_obj['functions']) > 10
            assert len(gz_obj['functions_src']) > 10

