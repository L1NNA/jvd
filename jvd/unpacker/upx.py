from jvd.resources import require, ResourceAbstract
from pathlib import Path
from typing import List
import platform
import os
from subprocess import check_output
from jvd.utils import get_file_type
from shutil import copyfile


class UPX(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/jinfeihan57/p7zip/releases/download/v17.03/linux-p7zip.zip'
        self.default = 'https://www.7-zip.org/a/7za920.zip'
        self.windows = 'https://www.7-zip.org/a/7z1900-x64.exe'
        self.check_update = False
        self.unpack = True

    def get(self):
        upx_dir = super().get()
        return {'windows': os.path.join(upx_dir, 'upx'),
                'linux': os.path.join(upx_dir,  'upx'),
                #    'darwin': [os.path.join(upx_dir,  'upx'), 'x']
                }[platform.system().lower()]


upx_c = require('upx')


def check_upx(file):
    upx_test = check_output([upx_c, '-t', file])
    return b'[OK]' in upx_test


def upx_unpack_if_applicable(file):
    if check_upx(file):
        dest = str(Path(file).with_suffix('')) + '_upx.bin'
        upx_action = check_output([upx_c, '-d', '-o', dest, file])
        if os.path.exists(dest) and b'Unpacked 1 file' in upx_action:
            os.remove(file)
            return dest
    return file
