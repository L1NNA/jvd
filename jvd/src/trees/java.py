import logging as log

import javalang
from jvd.src.defines import GraphExtractor
from jvd.utils import todict
import networkx as nx


class JavaASTExtractor(GraphExtractor):
    langs = ('java')

    def extract_graph(self, src):
        try:
            g = nx.Graph()
            tree = javalang.parse.parse(src)
            for path, node in tree:
                attrs = {
                    k: v for k, v in node.__dict__.items()
                    if not isinstance(v, (javalang.ast.Node, list)) and
                    v is not None and
                    len(str(v)) > 0 and
                    k not in ('_position')
                }
                attrs['type'] = node.__class__.__name__
                g.add_node(id(node), **attrs)
                if len(path) > 0:
                    parents = path[-1]
                    if not isinstance(path[-1], list):
                        parents = [parents]
                    for p in parents:
                        g.add_edge(id(p), id(node))
            # for n in g.nodes(data=True):
            #     print('!!', n)
            return g
        except Exception as e:
            log.error(e)
            return None
