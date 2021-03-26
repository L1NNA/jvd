import errno
import json
import logging as log
import os
import sys
from shutil import rmtree
from subprocess import PIPE, STDOUT, Popen

from jvd.disassembler import DisassemblerAbstract
from jvd.resources import require
from jvd.utils import check_output_ctx


class Ghidra(DisassemblerAbstract):

    def __init__(self):
        self.jar = require('ghidrajar')
        self.java = require('jdk')

    def _process(self, file, file_type, output_file_path, decompile=False):
        log = None
        js_file, log = process(
            self.java, self.jar, file,
            output_file_path, decompile=decompile, timeout=self.timeout*1.2)
        return js_file, log


def process(java, jar, file, json_file, project_suffix='.ghidra',
            decompile=False, func_entries=None, timeout=None):
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
            wf.writelines([str(l)+os.linesep for l in func_entries])
        cmd.append(func_entries_file)
    # p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    # out, err = p.communicate()
    # print(out.decode('utf-8'))
    with check_output_ctx(cmd, timeout=timeout) as out:
        out = out.decode('utf-8')
        json_file = None
        return json_file, out
