import datetime
import gzip
import hashlib
import json
import logging as log
import multiprocessing
import os
import platform
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from shutil import unpack_archive
from functools import partial

import magic
import requests
from tqdm import tqdm


def fn_from_url(url):
    return os.path.basename(urllib.parse.urlparse(url).path)


def download_file(url, dest, progress=False):

    if os.path.exists(dest) and progress:
        log.info('File already exists {} ...'.format(dest))
    else:
        if progress:
            log.info('downloading from: %s to %s', url, dest)

        r = requests.get(url, stream=True)
        total_length = r.headers.get('content-length')
        pg = tqdm(total=int(total_length)) if (
            total_length is not None and progress) else None
        dl = 0
        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    if progress and pg:
                        pg.update(len(chunk))
                    f.write(chunk)
                    f.flush()
        if progress and pg:
            pg.close()

    return dest


def read_gz_js(file):
    with gzip.open(file, 'r') as fin:
        json_bytes = fin.read()

    json_str = json_bytes.decode('utf-8')
    data = json.loads(json_str)
    return data


def write_gz_js(obj, file, cls=None):
    content = json.dumps(
        obj,
        cls=cls,
    ).encode('utf-8')
    with gzip.GzipFile(file, 'w') as gf:
        gf.write(content)


def get_file_type(file):
    if isinstance(file, str):
        return magic.from_file(file)
    else:
        return magic.from_buffer(file)


def which(program):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def sha256sum(filename):
    if isinstance(filename, str):
        h = hashlib.sha256()
        b = bytearray(128*1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            for n in iter(lambda: f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()
    else:
        return hashlib.sha256(filename).hexdigest()


def grep_ext(folder, ext=None):
    paths = [p for p in Path(
        folder).rglob('*') if p.is_file()]
    if ext:
        paths = [str(p) for p in paths if len(ext) < 1 or p.suffix == ext]
    else:
        paths = [str(p) for p in paths]
    return paths


def m_map(func, inputs, max_workers=-1,):
    if max_workers < 1:
        max_workers = multiprocessing.cpu_count()
    if platform.system() == 'Windows':
        # windows hard limit is 61
        max_workers = min(max_workers, 55)

    with ProcessPoolExecutor(max_workers=max_workers) as e:
        for ind, result in tqdm(enumerate(
                e.map(func, inputs)), total=len(inputs)):
            yield ind, result


class AttrDict(dict):
    """ Dictionary subclass whose entries can be accessed by attributes
        (as well as normally). (Added attributes will be ignored)
    """

    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

    @staticmethod
    def from_nested_dict(data):
        """ Construct nested AttrDicts from nested dictionaries. """
        if isinstance(data, dict):
            return AttrDict({key: AttrDict.from_nested_dict(data[key])
                             for key in data})
        if isinstance(data, list):
            return [AttrDict.from_nested_dict(d) for d in data]
        return data

    def __int__(self):
        if hasattr(self, 'addr_start'):
            return getattr(self, 'addr_start')
        return None


def toAttrDict(obj, classkey=None):
    obj_as_dict = todict(obj, classkey=classkey)
    return AttrDict.from_nested_dict(obj_as_dict)


def todict(obj, classkey=None):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict(v, classkey)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v, classkey) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value, classkey))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    else:
        return obj


class JVSample:

    def __init__(self, file, resource=None):
        parts = os.path.basename(file).split('.')
        original_name = str(Path(file).with_suffix('').name).replace('.', '_')
        self.file = file
        self.file_type = get_file_type(file)
        self._sha256 = sha256sum(file)
        if len(parts) < 4 or not file.endswith('.bin'):
            self.resource = resource if resource else original_name  # self._sha256
            self.labels = set(['na'])
            self.packers = set(['na'])
            self.save()
        else:
            self.resource = parts[0]
            self.labels = set(parts[1].split('-'))
            self.packers = set(parts[2].split('-'))

    def get_file_name(self,):
        base_name = '.'.join([
            self.resource,
            '-'.join(sorted(self.labels)),
            '-'.join(sorted(self.packers)),
            self.file_type.split()[0].lower(),
            'bin'
        ])
        return os.path.join(
            os.path.dirname(self.file),
            base_name
        )

    def save(self):
        new_file = self.get_file_name()
        os.rename(self.file, new_file)
        self.file = str(new_file)

    def add_label(self, new_label):
        new_label = new_label.strip()
        if not new_label or new_label == 'na' or len(new_label) == 0:
            return
        if len(self.labels) == 1 and list(self.labels)[0] == 'na':
            self.labels.clear()
        self.labels.add(new_label)
        self.save()

    def add_packer(self, new_label):
        new_label = new_label.strip()
        if not new_label or new_label == 'na' or len(new_label) == 0:
            return
        if len(self.packers) == 1 and list(self.packers)[0] == 'na':
            self.packers.clear()
        self.packers.add(new_label)
        self.save()

    def get_sha256(self):
        if self._sha256:
            return self._sha256
        sha256 = sha256sum(self.file)
        return sha256
