from pathlib import Path
import os
import requests
from lxml import html
from tqdm import tqdm
import urllib.request as ur
from zipfile import ZipFile
from jvd.ida.ida import IDA
import hashlib
import sys


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


def _ren_dis_entry(ext):
    for bin_file in os.listdir(ext):
        sha256, tp = os.path.splitext(os.path.basename(bin_file))
        target = os.path.join(ext, sha256+'.bin')
        source = os.path.join(ext, bin_file)
        if os.path.exists(target):
            os.remove(source)
        else:
            os.rename(
                source,
                target)


def _disassemble_all(path):
    disassember = IDA()
    disassember.disassemble_all(
        path, cfg=False, as_gzip=True,
    )


def _cleanup_all(ext):
    for bin_file in os.listdir(ext):
        bin_file = os.path.join(ext, bin_file)
        ext = Path(bin_file).suffix
        if ext in ['i64', 'id0', 'id1', 'id2', 'til', 'nam', 'json', '']:
            os.remove(bin_file)


if __name__ == '__main__':
    base = 'I:/benign'
    lines = []
    ds = []
    for d in os.listdir(base):
        d = os.path.join(base, d)
        for f in os.listdir(d):
            f = os.path.join(d, f)
            sha256 = sha256sum(f)
            if not os.path.exists(os.path.join(d, sha256+'.bin')):
                os.rename(f, os.path.join(d, sha256+'.bin'))
                lines.append(','.join([
                    sha256,
                    os.path.basename(d).replace(',', '_'),
                    os.path.basename(f).replace(',', '_'),
                ]))

        ds.append(d)
    with open(os.path.join(base, 'full.csv'), 'w') as wf:
        for l in lines:
            wf.write(l+'\n')

    for d in ds:
        _disassemble_all(d)
        _cleanup_all(d)