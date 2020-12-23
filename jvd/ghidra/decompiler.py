from jvd.ghidra.dependencies import install_jdk_if_needed
from jvd.ghidra.dependencies import install_jar_if_needed
import os
from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
import sys
import json
import errno
import logging as log
from jvd.disassembler import DisassemblerAbstract
from jvd.utils import home


NULL_FILE = open(os.devnull, 'w')
jar = install_jar_if_needed(
    home
)
java = install_jdk_if_needed(
    home
)


class Ghidra(DisassemblerAbstract):

    def _process(self, file, file_type, output_file_path, decompile=False):
        log = None
        js_file, log = process(file,  output_file_path, decompile=decompile)
        return js_file, log


def process(file, json_file, project_suffix='.ghidra',
            decompile=False, func_entries=None):
    project_dir = file + project_suffix

    file = os.path.abspath(file)
    json_file = os.path.abspath(json_file)
    project_dir = os.path.abspath(project_dir)

    if not os.path.exists(project_dir):
        os.mkdir(project_dir)
    cmd = [java, '-jar', jar, file, json_file,
           project_dir, str(decompile).lower()]
    if func_entries is not None:
        func_entries_file = file + '.func.entries.txt'
        with open(func_entries_file, 'w') as wf:
            wf.writelines(func_entries)
        cmd.append(func_entries_file)
    p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    out, err = p.communicate()
    # print(out.decode('utf-8'))
    out = out.decode('utf-8')
    json_file = None
    return json_file, out
