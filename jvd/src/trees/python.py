import ast
from os import walk

import networkx as nx
from jvd.src.defines import GraphExtractor


class NxWalker(ast.NodeVisitor):
    def __init__(self):
        self.stack = []
        self.graph = nx.Graph()

    def generic_visit(self, stmt):
        node_name = id(stmt)

        parent_name = None

        if self.stack:
            parent_name = self.stack[-1]

        self.stack.append(node_name)

        attributes = {
            k: v for k, v in stmt.__dict__.items()
            if not isinstance(v, (
                list,
                ast.AST
            )) and k not in {
                'lineno',
                'level',
                'col_offset'
            } and v is not None
        }
        attributes['type'] = stmt.__class__.__name__
        self.graph.add_node(node_name, **attributes)

        if parent_name:
            self.graph.add_edge(parent_name, node_name)

        super(self.__class__, self).generic_visit(stmt)

        self.stack.pop()


class PythonASTExtractor(GraphExtractor):

    def match_lang(self, lang):
        return lang in ('python', 'python2', 'python3')

    def extract_graph(self, src):
        tree = ast.parse(src)
        walker = NxWalker()
        walker.visit(tree)
        # for n in walker.graph.nodes(data=True):
        #     print('!!', n)
        return walker.graph
