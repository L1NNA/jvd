from pygments.lexers import get_all_lexers
from pygments.lexers import guess_lexer, LEXERS, get_lexer_by_name
from pygments.lexer import Lexer
from pygments.token import String, Comment, Number, Name
import re
import struct


def tokenize(src: str):
    return guess_lexer(src).get_tokens(src)


class GraphExtractor():

    def extract_graph(self, src):
        pass

    def match_lang(self, lang):
        pass


def str2num(t_type, t_val):
    if t_type in Number.Bin:
        t_val = re.sub(r'[^0-1]+', '', t_val)
        yield hex(int(t_val, 2))
    if t_type in Number.Float:
        t_val = re.sub(r'[^\d.]+', '', t_val)
        yield hex(struct.unpack('<I', struct.pack('<d', t_val))[0])
        yield hex(struct.unpack('<I', struct.pack('<f', t_val))[0])
    if t_type in Number.Hex:
        t_val = re.sub(r'[^0-1a-fA-F]+', '', t_val)
        yield t_val
    if t_type in Number.Integer:
        t_val = re.sub(r'[^0-9]+', '', t_val)
        yield hex(int(t_val))
    if t_type in Number.Oct:
        t_val = re.sub(r'[^0-7]+', '', t_val)
        yield hex(int(t_val, 8))


def guess_lang(src):
    lexer = guess_lexer(src.strip())
    return lexer.aliases[0]


# all short names
all_langs = [s for l in get_all_lexers() for s in l[1]]


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

    def gen_graph(self):
        if self.graph:
            return self.graph
        all_graph_extractors = [g() for g in GraphExtractor.__subclasses__()]
        extractors = [
            g for g in all_graph_extractors if g.match_lang(self.lang)]
        if len(extractors) > 0:
            self.graph = extractors[0].extract_graph(self.src)
        return self.graph

    def get_by_types(self, _type):
        return [t.strip() for t_cls, t in self.tokens
                if t_cls in _type and len(t.strip()) > 0]

    def get_numbers(self, ):
        vals = []
        for t_cls, t in self.tokens:
            if t_cls in Number:
                for _hex in str2num(t_cls, t):
                    vals.append(_hex)
        return vals

    def get_names(self):
        return self.get_by_types(Name)

    def get_comments(self):
        return self.get_by_types(Comment)

    def get_strings(self):
        return self.get_by_types(String)

    def merge_all(self, skip_comments=True):
        tokens = []
        for t_cls, t in self.tokens:
            if skip_comments and t_cls in Comment:
                continue
            if t_cls in Number:
                for _hex in str2num(t_cls, t):
                    tokens.append(_hex)
            else:
                if len(str(t).strip()) > 0:
                    tokens.append(t)
        return ' '.join(tokens)
