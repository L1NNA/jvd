
import threading
import logging as log
import os
import platform
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from shutil import copyfile, rmtree
from subprocess import DEVNULL, STDOUT, check_output
from typing import List

from unipacker.core import Sample, UnpackerEngine, SimpleClient
from unipacker.unpackers import AutomaticDefaultUnpacker, get_unpacker

from jvd.resources import ResourceAbstract, require
from jvd.utils import JVSample, get_file_type, grep_ext, redirect_std, check_output_ctx
import time
import traceback


class Unpacker:
    priority = 10
    timeout = 3 * 60

    def unpack_if_applicable(
            self, sample: JVSample, inplace=True) -> List[JVSample]:
        pass


class P7zip(ResourceAbstract, Unpacker):
    timeout = None  # ignore timeout for archive file
    priority = 0
    supported = (
        '7z', '7-zip', 'ace', 'adf', 'alzip', 'ape', 'ar', 'arc', 'arj',
        'bzip2', 'cab', 'chm', 'compress', 'cpio', 'deb', 'dms',
        'flac', 'gzip', 'iso', 'lrzip', 'lzh', 'lzip', 'lzma', 'lzop',
        'rpm', 'rzip', 'shar', 'shn', 'vhd', 'xz',
        'zip', 'zoo', 'zpaq',
        'gztar', 'rar'
    )

    def check_supported_archive(self, file_type):
        for s in self.supported:
            if file_type.lower().startswith(s):
                return s
        return None

    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/jinfeihan57/p7zip/releases/download/v17.03/linux-p7zip.zip'
        self.default = 'https://www.7-zip.org/a/7za920.zip'
        self.darwin = 'https://github.com/jinfeihan57/p7zip/releases/download/v17.03/macos-p7zip.zip'
        self.windows = 'https://www.7-zip.org/a/7z1900-x64.exe'
        self.check_update = False
        self.with_permission = True
        self.unpack = True
        self.x7z = None

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
                ], stderr=STDOUT)
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

    def unpack_if_applicable(
            self, sample: JVSample, inplace=True):
        packer = self.check_supported_archive(sample.file_type)
        if packer:  # and packer not in sample.packers:
            if not self.x7z:
                self.x7z = require('p7zip')
            unpack_dir = sample.file + '_unpack'
            if not os.path.exists(unpack_dir):
                cmd = [*self.x7z, sample.file, '-o' + unpack_dir]
                try:
                    with check_output_ctx(
                            cmd, timeout=self.timeout,
                            stdin=DEVNULL) as out_lines:
                        out_lines = out_lines.decode(
                            'ascii', 'ignore').splitlines()
                except:
                    if os.path.exists(unpack_dir):
                        rmtree(unpack_dir, True)
                    return [sample]
            sample.add_packer(packer)
            files: List[Path] = list(Path(unpack_dir).rglob("*.*"))
            files = [str(f) for f in files if f.is_file()]
            if inplace:
                files = [f for f in files if str(f).lower().endswith(('.exe', '.dll', '.pdf'))]
                if len(files) != 1:
                    if os.path.exists(unpack_dir):
                        rmtree(unpack_dir, True)
                    return [sample]
                else:
                    sample.replace(files[0])
                    rmtree(unpack_dir, True)
                    return [sample]
            samples = [JVSample(f) for f in files]
            for s in samples:
                s.save()
            return samples
        return [sample]


class UnTar(P7zip):
    priority = 1
    supported = ('tar',)


class UPX(ResourceAbstract, Unpacker):
    priority = 10

    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/upx/upx/releases/download/v3.96/upx-3.96-amd64_linux.tar.xz'
        self.default = self.linux
        self.windows = 'https://github.com/upx/upx/releases/download/v3.96/upx-3.96-win64.zip'
        self.check_update = False
        self.unpack = True
        self.upx_c = None

    def get(self):
        upx_dir = super().get()
        return {'windows': os.path.join(upx_dir, 'upx-3.96-win64', 'upx'),
                'linux': os.path.join(upx_dir, 'upx-3.96-amd64_linux', 'upx'),
                #    'darwin': [os.path.join(upx_dir,  'upx'), 'x']
                }[platform.system().lower()]

    def check_upx(self, file):
        if not self.upx_c:
            self.upx_c = require('upx')
        # upx_test = check_output([self.upx_c, '-t', file], stderr=STDOUT)
        # return b'[OK]' in upx_test
        with check_output_ctx(
                [self.upx_c, '-t', file], timeout=self.timeout) as upx_test:
            return b'[OK]' in upx_test

    def unpack_if_applicable(
            self, sample: JVSample, inplace=True):
        try:
            if 'upx' not in sample.packers and self.check_upx(sample.file):
                # dest = str(Path(file).with_suffix('')) + '_upx.bin'
                dest = sample.file + '_upx'
                # upx_action = check_output(
                #     [self.upx_c, '-d', '-o', dest, sample.file], stderr=STDOUT)
                with check_output_ctx(
                        [self.upx_c, '-d', '-o', dest, sample.file],
                        timeout=self.timeout) as upx_action:
                    if os.path.exists(dest) and b'Unpacked 1 file' in upx_action:
                        sample.add_packer('upx')
                        sample.replace(dest)
                        return [sample]
        except Exception as e:
            return [sample]
        return [sample]


class UniPacker(Unpacker):

    priority = 11

    def unpack_if_applicable(
            self, sample: JVSample, inplace=True):
        dest = sample.file + '_unipacker_'
        uni_sample = None
        if not sample.file_type.lower().startswith('pe'):
            return [sample]
        try:
            with redirect_std():
                uni_sample = Sample(
                    sample.file, True)
                unpacker = uni_sample.unpacker.__class__.__name__.lower().replace(
                    'unpacker', '')
            dest = dest + unpacker
            if not 'default' in unpacker and not unpacker in sample.packers:
                cmd = ['python', '-m', 'unipacker.shell',
                       sample.file, '-d', dest]
                with check_output_ctx(cmd, timeout=self.timeout) as uni_log:
                    if os.path.exists(dest):
                        files = os.listdir(dest)
                        if len(files) == 1:
                            sample.replace(os.path.join(dest, files[0]))
                        rmtree(dest)
                    sample.add_packer(unpacker)
                    return [sample]
                    # dest = str(Path(file).with_suffix('')) + '_upx.bin'
        except Exception as e:
            traceback.print_exc()
            print(str(e))
            if os.path.exists(dest):
                rmtree(dest)
        finally:
            # if uni_sample:
            #     tmp_file = uni_sample.unpacker.dumper.brokenimport_dump_file
            #     if os.path.exists(tmp_file):
            #         os.remove(tmp_file)
            pass

        return [sample]


all_unpackers = sorted(
    [c() for c in Unpacker.__subclasses__()], key=lambda x: x.priority)


def unpack_sample(sample: JVSample, inplace=True):
    samples = [sample]
    for up in all_unpackers:
        up: Unpacker
        new_samples = []

        for s in samples:
            r = up.unpack_if_applicable(s, inplace=inplace)
            new_samples.extend(r)
        samples = new_samples
    return samples
