import sys
import test.test_capa.tests.fixtures as fixtures
from test.test_capa.tests.fixtures import *
from functools import lru_cache
from jvd import get_disassembler
from jvd.capa import capa_analyze
from jvd.disassembler import DisassemblerAbstract


def test_jvd_field_missing():
    from jvd import get_disassembler
    from jvd.capa import JVDExtractor
    from jvd.disassembler import DisassemblerAbstract

    bin = os.path.join('test', 'test_jvd', 'zlib-1.2.7.o')
    extractor = capa_analyze(bin+'.json.gz', bin)
