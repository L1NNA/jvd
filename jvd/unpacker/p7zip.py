
from jvd.resources import require, ResourceAbstract
from pathlib import Path
from typing import List
import platform
import os
from subprocess import check_output
from jvd.utils import get_file_type, grep_ext
from shutil import copyfile, rmtree
from concurrent.futures import ProcessPoolExecutor


supported = (
    '7z', 'ace', 'adf', 'alzip', 'ape', 'ar', 'arc', 'arj',
    'bzip2', 'cab', 'chm', 'compress', 'cpio', 'deb', 'dms',
    'flac', 'gzip', 'iso', 'lrzip', 'lzh', 'lzip', 'lzma', 'lzop',
    'rpm', 'rzip', 'shar', 'shn', 'tar', 'vhd', 'xz',
    'zip', 'zoo', 'zpaq',
    'gztar', 'rar'
)


class P7zip(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/jinfeihan57/p7zip/releases/download/v17.03/linux-p7zip.zip'
        self.default = 'https://www.7-zip.org/a/7za920.zip'
        self.darwin = 'https://github.com/jinfeihan57/p7zip/releases/download/v17.03/macos-p7zip.zip'
        self.windows = 'https://www.7-zip.org/a/7z1900-x64.exe'
        self.check_update = False
        self.unpack = True

    def get(self):
        _sys = platform.system().lower()
        url = getattr(self, _sys)
        url = self.default if not url else url
        if _sys == 'windows':
            win_exe = self._download(
                self.windows, show_progress=True,
                unpack_if_needed=False)
            def_exe = self._download(
                self.default, show_progress=True,
                unpack_if_needed=True)
            unpacked = win_exe + '_unpacked'
            if not os.path.exists(unpacked):
                check_output([
                    os.path.join(def_exe, '7za'), 'x', win_exe, '-o' +
                    unpacked
                ])
            binary = unpacked
        else:
            binary = self._download(
                url, show_progress=True,
                unpack_if_needed=True)

        cmd = {'windows': [os.path.join(binary, '7z'), 'x'],
               'linux': [os.path.join(binary,  '7z'), 'x'],
               'darwin': [os.path.join(binary,  '7z'), 'x']
               }[platform.system().lower()]

        return cmd


x7z = require('p7zip')


def check_supported_archive(file_type):
    return file_type.lower().startswith(supported)


def unzip_if_applicable(
        file, file_type=None,
        keep_single_only=False,
        rename_ext=False,
        remove_original=False,
        rename_original=False):
    if not file_type:
        file_type = get_file_type(file)
    if rename_original:
        new_file = Path(file).with_suffix('.bin')
        os.rename(file, new_file)
        file = str(new_file)
    if check_supported_archive(file_type):
        unpack_dir = file + '_unpack'
        cmd = [*x7z, file, '-o' + unpack_dir]
        out_lines = check_output(cmd).decode('ascii', 'ignore').splitlines()
        files: List[Path] = list(Path(unpack_dir).rglob("*.*"))
        files = [str(f) for f in files if f.is_file()]
        if keep_single_only:
            if len(files) == 1:
                target = str(
                    Path(file).with_suffix('')) + '_unpack.bin'
                copyfile(files[0], target)
                rmtree(unpack_dir)
                if remove_original:
                    os.remove(file)
                return [target], out_lines
            else:
                rmtree(unpack_dir)
                if remove_original:
                    os.remove(file)
                return [], out_lines
        else:
            if remove_original:
                os.remove(file)
            return files, out_lines
    return [file], []
