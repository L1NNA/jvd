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
    paths = [str(p) for p in paths if len(ext) < 1 or p.suffix == ext]
    return paths


def m_map(func, inputs, max_workers=-1):
    if max_workers < 1:
        max_workers = multiprocessing.cpu_count()
    if platform.system() == 'Windows':
        # windows hard limit is 61
        max_workers = min(max_workers, 55)

    with ProcessPoolExecutor(max_workers=max_workers) as e:
        for ind, result in enumerate(
                e.map(func, inputs)):
            yield ind, result
