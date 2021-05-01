import os
from subprocess import PIPE, STDOUT, Popen
from tempfile import TemporaryDirectory
import networkx as nx
import pydot

from jvd.resources import ResourceAbstract
from jvd.src.defines import GraphExtractor
from jvd.utils import unzip_with_permission


class JoernCPPExtractor(ResourceAbstract, GraphExtractor):
    langs = ('cpp', 'c')

    def __init__(self):
        super().__init__()
        self.default = 'https://github.com/ShiftLeftSecurity/joern/releases/download/v1.1.123/joern-cli.zip'
        self.unpack = True
        self.with_permission = True

    def get(self):
        unpacked_dir = super().get()
        home = os.path.join(
            unpacked_dir, 'joern-cli'
        )
        exec_parse = os.path.join(
            unpacked_dir, 'joern-cli', 'joern-parse'
        )
        exec_export = os.path.join(
            unpacked_dir, 'joern-cli', 'joern-export'
        )
        return home, exec_parse, exec_export

    def extract(self, src, is_path=False):
        home, exec_parse, exec_export = self.get()

        with TemporaryDirectory() as temp_dir:

            file_name = 'test.cpp'
            prj_path = os.path.join(temp_dir, 'src')
            out_path = os.path.join(temp_dir, 'out')
            bin_path = os.path.join(temp_dir, 'cpg.bin')
            os.makedirs(prj_path)

            if is_path and os.path.isdir(src):
                prj_path = os.path.abspath(src)
            else:
                if is_path and os.path.isfile(src):
                    with open(src) as rf:
                        src = rf.read()
                with open(os.path.join(
                        prj_path, file_name), 'w') as outf:
                    outf.write(src)

            cmd = [exec_parse, prj_path, bin_path]
            p = Popen(cmd, stdout=PIPE, stderr=STDOUT, cwd=temp_dir)
            out, err = p.communicate()
            # print(out.decode('utf8'))
            cmd = [exec_export, bin_path]
            p = Popen(cmd, stdout=PIPE, stderr=STDOUT, cwd=temp_dir)
            out, err = p.communicate()
            graphs = {}
            for f in os.listdir(out_path):
                with open(os.path.join(out_path, f), 'r') as rf:
                    content = rf.read()
                    content = content.replace("digraph", 'digraph "', 1)
                    content = content.replace(" {", '" {', 1)
                    g = pydot.graph_from_dot_data(content)
                    if g is not None and len(g) > 0:
                        g = nx.drawing.nx_pydot.from_pydot(g[0])
                        key = g.graph['name']
                        if key in graphs:
                            key = key + f.split('-')[0]
                        graphs[key] = g
            # graph = nx.compose_all(graphs)
            # print(graph.nodes(data=True))
            return graphs

    def extract_graph(self, src):
        return self.extract(src, is_path=False)

    def extract_folder(self, folder):
        return self.extract(folder, is_path=True)
