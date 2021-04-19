import json
from pygments.lexers import get_all_lexers
from pygments.lexers import guess_lexer, LEXERS, get_lexer_by_name
from pygments.lexer import Lexer
from pygments.token import String, Comment, Number, Name
import re
import struct
import os
from jvd.utils import write_gz_js
import networkx as nx
from networkx.readwrite import json_graph


def tokenize(src: str):
    return guess_lexer(src).get_tokens(src)


class GraphExtractor():
    langs = (None)

    def extract_graph(self, src):
        pass

    def extract_folder(self, folder):
        pass

    def process_folder(self, folder):
        file = folder + '.ast.json.gz'
        if not os.path.exists(file):
            graphs = self.extract_folder(folder)
            for k in graphs:
                graphs[k] = json_graph.node_link_data(graphs[k])
            write_gz_js(graphs, file)
        return file


def str2num(t_type, t_val):
    if t_type in Number.Bin:
        t_val = re.sub(r'[^0-1]+', '', t_val)
        if len(t_val) > 0:
            yield hex(int(t_val, 2))
    if t_type in Number.Float:
        t_val = re.sub(r'[^\d.]+', '', t_val)
        if len(t_val) > 0:
            t_val = float(t_val)
            yield hex(struct.unpack('<Q', struct.pack('<d', t_val))[0])
            yield hex(struct.unpack('<I', struct.pack('<f', t_val))[0])
    if t_type in Number.Hex:
        t_val = re.sub(r'[^0-1a-fA-F]+', '', t_val)
        if len(t_val) > 0:
            yield hex(int(t_val, 16))
    if t_type in Number.Integer:
        t_val = re.sub(r'[^0-9]+', '', t_val)
        if len(t_val) > 0:
            yield hex(int(t_val))
    if t_type in Number.Oct:
        t_val = re.sub(r'[^0-7]+', '', t_val)
        if len(t_val) > 0:
            yield hex(int(t_val, 8))


def guess_lang(src):
    lexer = guess_lexer(src.strip())
    return lexer.aliases[0]


# all short names
all_langs = sorted([s for l in get_all_lexers() for s in l[1]])


class SourceFragment():
    def __init__(self, src, lang=None) -> None:
        self.src = src
        self.lang = ''
        self.tokens = []
        self.graph = None

        lexer: Lexer
        if not lang:
            lexer = guess_lexer(self.src.strip())
            self.lang = lexer.aliases[0]
        else:
            self.lang = lang
            lexer = get_lexer_by_name(self.lang)
        self.tokens = list(lexer.get_tokens(src))

    def gen_graph(self, merge=True):
        if self.graph:
            return self.graph
        extractors = [g() for g in GraphExtractor.__subclasses__()
                      if self.lang in g.langs]
        if len(extractors) > 0:
            self.graph = extractors[0].extract_graph(self.src)
        if isinstance(self.graph, dict):
            self.graph = nx.compose_all(self.graph.values())
        return self.graph

    def get_by_types(self, _type):
        return [t.strip() for t_cls, t in self.tokens
                if t_cls in _type and len(t.strip()) > 0]

    def get_numbers(self, ):
        vals = []
        for t_cls, t in self.tokens:
            if t_cls in Number:
                for _hex in str2num(t_cls, t):
                    if _hex.startswith('0x'):
                        _hex = _hex[2:]
                    vals.append(_hex)
        return vals

    def get_names(self):
        return self.get_by_types(Name)

    def get_comments(self):
        return self.get_by_types(Comment)

    def get_strings(self):
        return self.get_by_types(String)

    def merge_all(self, skip_comments=True):
        tokens = [*self.get_strings(), *self.get_names()]
        numbers = self.get_numbers()
        if len(numbers) > 10:
            numbers = [n for n in numbers if len(n) > 4]
        tokens.extend(numbers)
        return tokens


def process_folder(folder, lang):
    extractors = [g() for g in GraphExtractor.__subclasses__()
                  if lang in g.langs]
    if len(extractors) > 0:
        extractors[0].process_folder(folder)
    else:
        raise Exception('no extractor found for', lang)
