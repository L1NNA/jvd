import json
from io import BytesIO
from capa.features.common import ARCH_AMD64, ARCH_I386, Arch, Feature
import os
from collections import defaultdict
from shutil import unpack_archive

import capa
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress
from capa.features.common import (ARCH_ANY, FORMAT_ELF, FORMAT_FREEZE,
                                  FORMAT_PE, FORMAT_RESULT, OS, OS_ANY,
                                  OS_AUTO, OS_WINDOWS, Arch, Feature, Format,
                                  String)
from capa.features.extractors.base_extractor import FeatureExtractor
from capa.main import (UnsupportedRuntimeError, find_capabilities, get_rules,
                       has_file_limitation)

import jvd.capa.block as e_block
import jvd.capa.file as e_file
import jvd.capa.function as e_func
import jvd.capa.ins as e_ins
from jvd.capa.data import DataUnit
from jvd.resources import ResourceAbstract, require
from jvd.utils import download_file, get_file_type, read_gz_js
from functools import cache


@cache
def get_rules(verbose):
    rule_path = install_rules(verbose)
    rules = capa.main.get_rules([rule_path])
    if isinstance(rules, list):
        rules = capa.rules.RuleSet(rules)
    return rules


class CapaRules(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.version = 'v5.1.0'
        self.default = 'https://github.com/fireeye/capa-rules/archive/{}.zip'.format(
            self.version)
        self.check_update = False
        self.unpack = True

    def get(self):
        folder = super().get()
        return os.path.join(folder, 'capa-rules-{}'.format(self.version[1:]))


class JVDExtractor(FeatureExtractor):
    def __init__(self, gz_file, bin_path):
        super(JVDExtractor, self).__init__()
        if isinstance(gz_file, str):
            gz_file = read_gz_js(gz_file)
        self.data_unit = DataUnit(gz_file, bin_path)
        self.global_features = []
        file_format = get_file_type(bin_path).lower().split(',')[0]
        if 'pe' in file_format:
            self.global_features.append((Format(FORMAT_PE), NO_ADDRESS))
            self.global_features.append((OS(OS_WINDOWS), NO_ADDRESS))
        elif 'elf' in file_format:
            self.global_features.append((Format(FORMAT_ELF), NO_ADDRESS))
            with open(bin_path, "rb") as fh:
                buf = BytesIO(fh.read())
                os = capa.features.extractors.elf.detect_elf_os(buf)
                if os in capa.features.common.VALID_OS:
                    self.global_features.append((OS(os), NO_ADDRESS))
        arch = self.data_unit.obj.bin.architecture.lower()
        bits = str(self.data_unit.obj.bin.bits)
        if 'amd64' in arch or 'x86_64' in arch:
            self.global_features.append((Arch(ARCH_AMD64), NO_ADDRESS))
        elif 'i386' in arch:
            self.global_features.append((Arch(ARCH_I386), NO_ADDRESS))
        if 'metapc' in arch:
            if '32' in bits:
                self.global_features.append((Arch(ARCH_I386), NO_ADDRESS))
            else:
                self.global_features.append((Arch(ARCH_AMD64), NO_ADDRESS))

    def get_base_address(self):
        return self.data_unit.obj.base

    def extract_file_features(self):
        for feature, va in e_file.extract_features(self.data_unit):
            yield feature, va

    def get_functions(self):
        for function in self.data_unit.obj.functions:
            yield function

    def extract_function_features(self, f):
        for feature, va in e_func.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        for bb in f.blocks:
            yield bb

    def extract_basic_block_features(self, f, bb):
        for feature, va in e_block.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        for i in bb.ins:
            yield i

    def extract_insn_features(self, f, bb, insn):
        for feature, va in e_ins.extract_features(f, bb, insn):
            yield feature, va

    def extract_features(self, function_addr=None):
        all_features = defaultdict(list)
        functions_features = []
        bb_features = []
        insn_features = []
        file_features = []
        if function_addr is None:
            file_features = list(self.extract_file_features())

        functions = self.get_functions()
        for function in functions:
            if function_addr is None or function['addr_start'] == function_addr:
                functions_features.extend(
                    list(self.extract_function_features(function)))
                basic_blocks = self.get_basic_blocks(function)
                for basic_block in basic_blocks:
                    bb_features.extend(
                        list(self.extract_basic_block_features(function, basic_block)))
                    instructions = self.get_instructions(
                        function, basic_block)
                    for instruction in instructions:
                        insn_features.extend(
                            list(self.extract_insn_features(function, basic_block, instruction)))

        for feat, addr in file_features+functions_features+bb_features+insn_features:
            all_features[addr].append(feat)
        return dict(all_features)

    def extract_global_features(self):
        yield from self.global_features


def install_rules(verbose=-1):
    return require('caparules')


def capa_analyze(gz_file, bin_path, verbose=-1):

    rs = get_rules(verbose)
    extractor = JVDExtractor(gz_file, bin_path)
    capabilities, counts = find_capabilities(
        rs, extractor, disable_progress=verbose < 1)

    docs = []

    items = [(dict(rs[r_name].meta), matches)
             for r_name, matches in capabilities.items()]

    all_caps = []

    for meta, matches in items:

        if meta.get("capa/subscope-rule"):
            continue
        if meta.get("lib"):
            continue
        if meta.get("maec/analysis-conclusion"):
            continue
        if meta.get("maec/analysis-conclusion-ov"):
            continue
        if meta.get("capa/subscope"):
            continue

        # doc = (meta, )
        doc = meta

        meta['capa/path'] = os.path.abspath(meta['capa/path']).replace(
            os.path.abspath(
                '/capa/rules/'), ''
        )

        loc = defaultdict(list)

        for _, m in matches:
            for l, statement in collect_locations(m):
                loc[str(l)].append(statement)
        doc['loc'] = loc
        if 'examples' in doc:
            del doc['examples']
        if 'author' in doc:
            del doc['author']
        # del doc['scope']
        if 'references' in doc:
            del doc['references']
        if 'namespace' in doc:
            del doc['namespace']

        all_caps.append(doc)

    return all_caps


def collect_locations(result):
    if result.success:
        for l in result.locations:
            yield l, str(result.statement)
    for c in result.children:
        for l, st in collect_locations(c):
            yield l, st

