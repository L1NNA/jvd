from ghidrapy.dependencies import install_jdk_if_needed
from ghidrapy.dependencies import install_jar_if_needed
import os
from pathlib import Path
from subprocess import call
from shutil import rmtree
import sys


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


def process(file, json_suffix='.asm.json', project_suffix='.ghidra'):
    json_file = file + json_suffix
    project_dir = file + project_suffix

    json_file = os.path.abspath(json_file)
    project_dir = os.path.abspath(project_dir)

    if not os.path.exists(project_dir):
        os.mkdir(project_dir)
    cmd = [java, '-jar', jar, file, json_file, project_dir]
    call(cmd,
         stdout=NULL_FILE,
         stderr=sys.stderr)
    return json_file


def cleanup(file, project_only=True, json_suffix='.asm.json', project_suffix='.ghidra'):
    json_file = file + json_suffix
    project_dir = file + project_suffix
    rmtree(project_dir)
    if not project_only:
        os.remove(json_file)
