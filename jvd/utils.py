import datetime
import gzip
import json
import logging as log
import os
import platform
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from shutil import unpack_archive

import requests
from dateutil.parser import parse as parsedate
from dateutil.tz import tzlocal
from tqdm import tqdm

home = os.path.join(
    str(Path.home()), 'jvd-dependencies'
)


def fn_from_url(url):
    return os.path.basename(urllib.parse.urlparse(url).path)


def download_file(url, dest_path=home, progress=False):
    if not os.path.exists(dest_path):
        os.makedirs(dest_path)

    if progress:
        log.info('downloading from: %s', url)

    fn = fn_from_url(url)
    full_fn = os.path.join(dest_path, fn)

    if os.path.exists(full_fn):
        log.info('File %s already exists in %s ...' % (fn, dest_path))
    else:
        r = requests.get(url, stream=True)
        total_length = r.headers.get('content-length')
        pg = tqdm(total=int(total_length)) if (
            total_length is not None and progress) else None
        dl = 0
        with open(full_fn, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    if progress and pg:
                        pg.update(len(chunk))
                    f.write(chunk)
                    f.flush()
        if progress and pg:
            pg.close()

    return full_fn


def read_gz_js(file):
    with gzip.open(file, 'r') as fin:
        json_bytes = fin.read()

    json_str = json_bytes.decode('utf-8')
    data = json.loads(json_str)
    return data
