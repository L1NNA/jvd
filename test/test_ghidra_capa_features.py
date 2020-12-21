# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import test.test_capa.tests.fixtures as fixtures
from test.test_capa.tests.fixtures import *
from functools import lru_cache


def get_function_jvd(extractor, fva):
    for f in extractor.get_functions():
        if f.addr_start == fva:
            return f
    for f in extractor.get_functions():
        for b in f.blocks:
            for i in b.ins:
                if i.ea == fva:
                    return f
    raise ValueError("function not found")


fixtures.get_function = get_function_jvd


@lru_cache()
def get_jvd_ghidra_extractor(path):
    from jvd import get_disassembler
    from jvd.capa import JVDExtractor
    from jvd.disassembler import DisassemblerAbstract

    disassembler = get_disassembler(disassembler='ghidra')
    disassembler: DisassemblerAbstract
    gz_file, logs = disassembler.disassemble(path, cleanup=False, additional_ext='.ghr')
    extractor = JVDExtractor(gz_file, path)
    return extractor


@parametrize(
    "sample,scope,feature,expected",
    FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_jvd_ghidra_features(sample, scope, feature, expected):
    with xfail(sys.version_info < (3, 0), reason="JVD only works on py3"):
        do_test_feature_presence(
            get_jvd_ghidra_extractor, sample, scope, feature, expected)


@parametrize(
    "sample,scope,feature,expected",
    FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_jvd_ghidra_feature_counts(sample, scope, feature, expected):
    with xfail(sys.version_info < (3, 0), reason="JVD only works on py3"):
        do_test_feature_count(get_jvd_ghidra_extractor,
                              sample, scope, feature, expected)
