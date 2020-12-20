import os
from shutil import unpack_archive

import jvd.capa.block as e_block
import jvd.capa.file as e_file
import jvd.capa.function as e_func
import jvd.capa.ins as e_ins
from jvd.capa.data import DataUnit
from jvd.utils import download_file, home, read_gz_js

import capa
from capa.features.extractors import FeatureExtractor
from capa.main import (UnsupportedRuntimeError, find_capabilities, get_rules,
                       has_file_limitation)
from capa.render import convert_match_to_result_document, CapaJsonObjectEncoder


url_rules = 'https://github.com/fireeye/capa-rules/archive/v1.4.0.zip'
rules = []


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
    rules_path = os.path.join(home, 'capa-rules')
    f_name = download_file(url=url_rules, progress=verbose > 0)
    unpack_archive(f_name, rules_path)
    return rules_path


def capa_analyze(gz_file, bin_path, verbose=-1):
    if len(rules) < 1:
        rules.extend(get_rules(install_rules(verbose),
                               disable_progress=verbose < 1))
    rs = capa.rules.RuleSet(rules)
    extractor = JVDExtractor(gz_file, bin_path)
    capabilities, counts = find_capabilities(
        rs, extractor, disable_progress=verbose < 1)

    docs = []

    # (rule_name, matches)
    items = [(dict(rs[r_name].meta), matches) for r_name, matches in capabilities.items()]
    items.sort(key=lambda i: (i[0].get('namespace' ,''), i[0].get('name', '')))

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

        doc = (meta, )

        if meta.get("att&ck"):
            tactics.append(doc)
        elif meta.get("mbc"):
            mbcs.append(doc)
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


def convert_match_to_result_document(rules, capabilities, result):
    """
    convert the given Result instance into a common, Python-native data structure.
    this will become part of the "result document" format that can be emitted to JSON.
    """
    doc = {
        "success": bool(result.success),
        "node": convert_node_to_result_document(result.statement),
        "children": [convert_match_to_result_document(rules, capabilities, child) for child in result.children],
    }

    # logic expression, like `and`, don't have locations - their children do.
    # so only add `locations` to feature nodes.
    if isinstance(result.statement, capa.features.Feature):
        if bool(result.success):
            doc["locations"] = result.locations
    elif isinstance(result.statement, capa.rules.Range):
        if bool(result.success):
            doc["locations"] = result.locations

    # if we have a `match` statement, then we're referencing another rule.
    # this could an external rule (written by a human), or
    #  rule generated to support a subscope (basic block, etc.)
    # we still want to include the matching logic in this tree.
    #
    # so, we need to lookup the other rule results
    # and then filter those down to the address used here.
    # finally, splice that logic into this tree.
    if (
        doc["node"]["type"] == "feature"
        and doc["node"]["feature"]["type"] == "match"
        # only add subtree on success,
        # because there won't be results for the other rule on failure.
        and doc["success"]
    ):

        rule_name = doc["node"]["feature"]["match"]
        rule = rules[rule_name]
        rule_matches = {address: result for (
            address, result) in capabilities[rule_name]}

        if rule.meta.get("capa/subscope-rule"):
            # for a subscope rule, fixup the node to be a scope node, rather than a match feature node.
            #
            # e.g. `contain loop/30c4c78e29bf4d54894fc74f664c62e8` -> `basic block`
            scope = rule.meta["scope"]
            doc["node"] = {
                "type": "statement",
                "statement": {
                    "type": "subscope",
                    "subscope": scope,
                },
            }

        for location in doc["locations"]:
            doc["children"].append(convert_match_to_result_document(
                rules, capabilities, rule_matches[location]))

    return doc
