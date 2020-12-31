import subprocess
import os
from shutil import copytree, unpack_archive
from pathlib import Path
import tempfile
import logging as log


path_current = os.path.dirname(os.path.abspath(__file__))


def install():
    with tempfile.TemporaryDirectory() as tmpdirname:

        unpack_archive(path_current, tmpdirname)
        path_wheel = os.path.join(tmpdirname, 'wheels')
        path_cache = os.path.join(tmpdirname, 'libs')
        print('debugging purpose:', os.listdir(tmpdirname))

        print('installing python packages...')
        cmd = [
            'python', '-m', 'pip', 'install', '--no-index', '--find-links', path_wheel, '{package}'
        ]
        subprocess.run(cmd)
        lib_home = os.path.join(str(Path.home()), 'jv-dependencies')
        if os.path.exists(lib_home):
            print('{} exists. please double check and remove.'.format(lib_home))
        else:
            print('installing dependencies to ' + lib_home)
            copytree(path_cache, lib_home)


if __name__ == '__main__':
    install()
