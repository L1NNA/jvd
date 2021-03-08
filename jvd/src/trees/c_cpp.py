import os
from subprocess import PIPE, STDOUT, Popen
from tempfile import TemporaryDirectory
from zipfile import ZipFile, ZipInfo
import networkx as nx
import pydot

from jvd.resources import ResourceAbstract
from jvd.src.defines import GraphExtractor


class ZipFileWithPermissions(ZipFile):
    def _extract_member(self, member, targetpath, pwd):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        targetpath = super()._extract_member(member, targetpath, pwd)

        attr = member.external_attr >> 16
        if attr != 0:
            os.chmod(targetpath, attr)
        return targetpath


class JoernCPPExtractor(ResourceAbstract, GraphExtractor):
    def __init__(self):
        super().__init__()
        self.default = 'https://github.com/ShiftLeftSecurity/joern/releases/download/v1.1.123/joern-cli.zip'
        self.unpack = False

    def get(self):
        zip_file = super().get()
        unpacked_dir = zip_file + '_unpacked'
        if not os.path.exists(unpacked_dir):
            with ZipFileWithPermissions(zip_file) as zfp:
                zfp.extractall(unpacked_dir)
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

    def match_lang(self, lang):
        return lang in ('cpp', 'c')

    def extract_graph(self, src):
        file_name = 'test.cpp'
        home, exec_parse, exec_export = self.get()

        with TemporaryDirectory() as temp_dir:

            prj_path = os.path.join(temp_dir, 'src')
            out_path = os.path.join(temp_dir, 'out')
            bin_path = 'cpg.bin'
            os.makedirs(prj_path)
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
            graphs = []
            for f in os.listdir(out_path):
                with open(os.path.join(out_path, f), 'r') as rf:
                    content = rf.read()
                    content = content.replace("digraph", 'digraph "', 1)
                    content = content.replace(" {", '" {', 1)
                    g = pydot.graph_from_dot_data(content)
                    if len(g) > 0:
                        g = nx.drawing.nx_pydot.from_pydot(g[0])
                        graphs.append(g)
            graph = nx.compose_all(graphs)
            # print(graph.nodes(data=True))
            return graph
