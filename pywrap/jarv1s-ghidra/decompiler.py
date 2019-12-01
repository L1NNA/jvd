from dependencies import install_jdk
import os
from pathlib import Path
from subprocess import call
from shutil import rmtree


NULL_FILE = open(os.devnull, 'w')
home = os.path.join(
    str(Path.home()), '.jarv1s-ghidra'
    )
jar = os.path.join(
    os.path.realpath(__file__), 'jarv1s-ghidra.jar'
    )
java = install_jdk(
    home
    )


 def process(file):
    json_file = file + '.asm.json'
    project_dir = file + '.ghidra'
    if not os.path.exist(project_dir):
        os.mkdir(project_dir)
    cmd = [java, '-jar', jar, file, json_file, project_dir]
    print(cmd)
    call(
    ['ida64', '-A', '-S{}'.format(IDA_script), file],
    stdout=NULL_FILE,
    stderr=sys.stderr)
    return json_file


def cleanup(file):
    json_file = file + '.asm.json'
    project_dir = file + '.ghidra'
    rmtree(project_dir)
    os.remove(json_file)

    
