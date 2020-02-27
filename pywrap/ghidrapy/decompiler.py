from ghidrapy.dependencies import install_jdk_if_needed
from ghidrapy.dependencies import install_jar_if_needed
import os
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT
from shutil import rmtree
import sys
import json
import errno


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
    out, _ = p.communicate()
    if os.path.exists(json_file):
        if load:
            with open(json_file) as of:
                json_file = json.load(of)
    else:
        # raise FileNotFoundError(
        #     errno.ENOENT, os.strerror(errno.ENOENT), json_file)
        json_file = None
    return json_file, out


def cleanup(file, project_only=True, json_suffix='.asm.json',
            project_suffix='.ghidra'):
    json_file = file + json_suffix
    project_dir = file + project_suffix
    rmtree(project_dir)
    if not project_only:
        os.remove(json_file)
