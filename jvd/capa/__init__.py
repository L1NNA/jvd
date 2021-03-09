import os
from shutil import unpack_archive
from collections import defaultdict

import jvd.capa.block as e_block
import jvd.capa.file as e_file
import jvd.capa.function as e_func
import jvd.capa.ins as e_ins
from jvd.capa.data import DataUnit
from jvd.utils import download_file, read_gz_js
from jvd.resources import ResourceAbstract, require

import capa
from capa.features.extractors import FeatureExtractor
from capa.main import (UnsupportedRuntimeError, find_capabilities, get_rules,
                       has_file_limitation)
from capa.render import convert_match_to_result_document, CapaJsonObjectEncoder


rules = []


class CapaRules(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.version = 'v1.5.1'
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


def install_rules(verbose=-1):
    return require('caparules')


def capa_analyze(gz_file, bin_path, verbose=-1):

    rule_path = install_rules(verbose)

    if len(rules) < 1:
        rules.extend(get_rules(rule_path,
                               disable_progress=verbose < 1))
    rs = capa.rules.RuleSet(rules)
    extractor = JVDExtractor(gz_file, bin_path)
    capabilities, counts = find_capabilities(
        rs, extractor, disable_progress=verbose < 1)

    docs = []

    # (rule_name, matches)
    items = [(dict(rs[r_name].meta), matches)
             for r_name, matches in capabilities.items()]
    items.sort(key=lambda i: (i[0].get('namespace', ''), i[0].get('name', '')))

    tactics = []
    mbcs = []
    caps = []

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
                rule_path), ''
            # 'https://github.com/fireeye/capa-rules/blob/master'
        )

        loc = defaultdict(list)

        for _, m in matches:
            for l, statement in collect_locations(m):
                loc[l].append(statement)
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

        if meta.get("mbc"):
            mbcs.append(doc)
        elif meta.get("att&ck"):
            tactics.append(doc)
        else:
            caps.append(doc)

    # docs.append(
    #     {
    #         "meta": dict(rule.meta),
    #         "matches": {
    #             addr: convert_match_to_result_document(rs, capabilities, match) for (addr, match) in matches
    #         },
    #     })

    return {'tac': tactics, 'mbc': mbcs, 'cap': caps}


def collect_locations(result):
    if result.success:
        for l in result.locations:
            yield l, str(result.statement)
    for c in result.children:
        for l, st in collect_locations(c):
            yield l, st
