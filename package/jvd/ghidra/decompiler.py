from jvd.ghidra.dependencies import install_jdk_if_needed
from jvd.ghidra.dependencies import install_jar_if_needed
import os
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
import sys
import json
import errno
import logging as log
from jvd.disassembler import DisassemblerAbstract


NULL_FILE = open(os.devnull, 'w')
home = os.path.join(
    str(Path.home()), '.jarv1s-ghidra'
)
jar = install_jar_if_needed(
    home
)
java = install_jdk_if_needed(
    home
)


class Ghidra(DisassemblerAbstract):

    def cleanup(self, file):
        _cleanup(file, project_only=True)

    def _process(self, file, file_type, decompile=False):
        log = None
        js_file = os.path.join(
            os.path.dirname(file),
            os.path.basename(file) + '.asm.json')
        if not os.path.exists(js_file):
            js_file, log = process(file, decompile=decompile)
        return js_file, log


def process(file, json_suffix='.asm.json', project_suffix='.ghidra',
            decompile=False, load=False):
    json_file = file + json_suffix
    project_dir = file + project_suffix

    json_file = os.path.abspath(json_file)
    project_dir = os.path.abspath(project_dir)

    if not os.path.exists(project_dir):
        os.mkdir(project_dir)
    cmd = [java, '-jar', jar, file, json_file,
           project_dir, str(decompile).lower()]
    p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    out, err = p.communicate()
    if os.path.exists(json_file):
        if load:
            with open(json_file) as of:
                json_file = json.load(of)
    else:
        log.error(
            'No json file generated. Info: {} Err: {}'.format(
                out, err))
        json_file = None
    return json_file, out


def _cleanup(file, project_only=True, json_suffix='.asm.json',
             project_suffix='.ghidra'):
    json_file = file + json_suffix
    project_dir = file + project_suffix
    rmtree(project_dir)
    if not project_only:
        os.remove(json_file)
