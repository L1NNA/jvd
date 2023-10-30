import datetime
import gzip
import hashlib
import io
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
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from functools import partial
from multiprocessing import Pool
from pathlib import Path
from shutil import unpack_archive
from subprocess import PIPE, STDOUT, Popen, TimeoutExpired
from zipfile import ZipFile, ZipInfo
import psutil

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


def read_gz_js(file, as_attrdict=False):
    with gzip.open(file, 'r') as fin:
        json_bytes = fin.read()

    json_str = json_bytes.decode('utf-8')
    data = json.loads(json_str)
    if as_attrdict:
        return AttrDict.from_nested_dict(data)
    return data


def write_gz_js(obj, file, cls=None):
    content = json.dumps(
        obj,
        cls=cls,
    ).encode('utf-8')
    with gzip.GzipFile(file, 'w') as gf:
        gf.write(content)


def get_file_type(file):
    if isinstance(file, Path):
        file = str(file.resolve())
    try:
        if isinstance(file, str):
            file_type = magic.from_file(file)
        else:
            file_type = magic.from_buffer(file)

        if file_type.startswith('data'):
            if isinstance(file, str):
                with open(file, 'rb') as rf:
                    if rf.read(5).startswith(b'IDA2'):
                        file_type = 'IDA64 (Interactive Disassembler) database'
        return file_type
    except:
        return 'unknown'


def get_file_size(file):
    if isinstance(file, Path):
        file = str(file.resolve())
    if isinstance(file, str):
        return os.path.getsize(file)
    else:
        return len(file)


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
    if isinstance(filename, Path):
        filename = str(filename.resolve())
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


def grep_ext(folder, ext=None, type='f'):
    if type == 'f':
        paths = [p for p in Path(
            folder).rglob('*') if p.is_file()]
    elif type == 'd':
        paths = [p for p in Path(
            folder).rglob('*') if p.is_dir()]
    if ext is not None:
        ext = ext.strip()
        if len(ext) > 0:
            paths = [str(p) for p in paths if
                     p.suffix == ext or str(p).endswith(ext)]
        else:
            paths = [str(p) for p in paths if not '.' in p.name]
    else:
        paths = [str(p) for p in paths]
    return paths


def m_map(func, inputs, max_workers=-1, show_progress_bar=False):
    if max_workers < 1:
        max_workers = multiprocessing.cpu_count()
    if platform.system() == 'Windows':
        # windows hard limit is 61
        max_workers = min(max_workers, 59)

    with Pool(max_workers) as e:
        pbar = enumerate(
            e.imap_unordered(func, inputs))
        if show_progress_bar:
            pbar = tqdm(pbar, total=len(inputs))
        for ind, result in pbar:
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

    def __getattr__(self, key):
        if key == 'address':
            if hasattr(self, 'ea'):
                return self['ea']
            if hasattr(self, 'addr_start'):
                return self['addr_start']
        raise AttributeError


def toAttrDict(obj, classkey=None):
    obj_as_dict = todict(obj, classkey=classkey)
    return AttrDict.from_nested_dict(obj_as_dict)


def todict(obj, classkey=None, format_datetime=False):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            if isinstance(k, Path):
                k = str(k)
            data[k] = todict(v, classkey, format_datetime)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast(), format_datetime)
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v, classkey, format_datetime) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value, classkey, format_datetime))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    else:
        if isinstance(obj, datetime.datetime) and format_datetime:
            return obj.strftime("%Y-%m-%d %H:%M")
        elif isinstance(obj, Path):
            return str(obj)
        else:
            return obj


class JVSample:

    def __init__(self, file, resource=None):
        self.file = file
        self.file_type = get_file_type(file)
        self.hash = sha256sum(file)
        parts = os.path.basename(file).split('.')
        if len(parts) < 5 or not file.endswith('.bin'):
            ext = Path(file).suffix
            if len(ext) > 0:
                ext = ext[1:]
            if isinstance(resource, JVSample):
                self.resource = resource.hash
            elif resource:
                self.resource = resource
            else:
                self.resource = Path(file).with_suffix(
                    '').name.replace('.', '_')
            self.labels = set(['na'])
            self.packers = set(['na'])
            self.ext = ext.replace('.', '_')
        else:
            self.resource = parts[0]
            self.labels = set(parts[1].split('-'))
            self.packers = set(parts[2].split('-'))
            self.ext = parts[3]

    def get_file_name(self,):
        base_name = '.'.join([
            self.resource,
            '-'.join(sorted(self.labels)),
            '-'.join(sorted(self.packers)),
            self.ext,
            self.file_type.split()[0].lower().replace('/', '_'),
            'bin'
        ])
        return os.path.join(
            os.path.dirname(self.file),
            base_name
        )

    def save(self):
        new_file = self.get_file_name()
        if not os.path.abspath(self.file) == os.path.abspath(new_file):
            os.rename(self.file, new_file)
            self.file = str(new_file)

    def add_labels(self, new_labels):
        new_labels = [l.strip().replace('.', '_').replace('-', '_') for l in new_labels
                      if l != 'na' and len(l.strip()) > 0]
        if len(new_labels) < 1:
            return
        if len(self.labels) == 1 and list(self.labels)[0] == 'na':
            self.labels.clear()
        self.labels.update(new_labels)
        self.save()

    def add_packer(self, new_label):
        new_label = new_label.strip().replace('.', '_').replace('-', '_')
        if not new_label or new_label == 'na' or len(new_label) == 0:
            return
        if len(self.packers) == 1 and list(self.packers)[0] == 'na':
            self.packers.clear()
        self.packers.add(new_label)
        self.save()

    def replace(self, file):
        os.remove(self.file)
        self.file_type = get_file_type(file)
        self.hash = sha256sum(file)
        ext = Path(file).suffix
        if len(ext) > 0:
            ext = ext[1:]
        self.ext = ext.replace('.', '_')
        os.rename(file, self.file)
        self.save()


@contextmanager
def redirect_std():
    f = io.StringIO()
    with redirect_stdout(f):
        with redirect_stderr(f):
            yield f


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


@contextmanager
def check_output_ctx(cmd, timeout=None, env=None, stdin=None, live=False):
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=None if live else PIPE, stderr=STDOUT, env=env,
            stdin=stdin)
        outputs, _ = proc.communicate(timeout=timeout)
        yield outputs
    except TimeoutExpired as te:
        try:
            kill(proc.pid)
        except Exception as e:
            pass
        raise te
    finally:
        pass


class ZipFileWithPermissions(ZipFile):
    def _extract_member(self, member, targetpath, pwd):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        targetpath = super()._extract_member(member, targetpath, pwd)

        attr = member.external_attr >> 16
        if attr != 0:
            os.chmod(targetpath, attr)
        return targetpath


def unzip_with_permission(zip_file, dest):
    if not os.path.exists(dest):
        with ZipFileWithPermissions(zip_file) as zfp:
            zfp.extractall(dest)
    return dest
