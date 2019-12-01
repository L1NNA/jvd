import os
import urllib.request
import urllib.parse
import urllib.error
import urllib.parse
import requests
import platform
import logging as log
from tqdm import tqdm
from shutil import unpack_archive
import subprocess
import re


def fn_from_url(url):
    return os.path.basename(urllib.parse.urlparse(url).path)


def download_file(url, dest_path, progress=False):
    if not os.path.exists(dest_path):
        os.makedirs(dest_path)

    if progress:
        logging.info('downloading from: %s', url)

    fn = fn_from_url(url)
    full_fn = os.path.join(dest_path, fn)

    if os.path.exists(full_fn):
        logging.info('File %s already exists in %s ...' % (fn, dest_path))
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


def install_jdk(path, version='13.0.1'):
    version = subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT)
    pattern = '\"(\d+\.\d+).*\"'
    val = re.search(pattern, version).groups()[0]
    val = double(val)
    if val >= 11:
        return 'java'

    if not os.path.exists(path):
        os.mkdir(path)

    java = {
        'linux': 'jdk-{}/bin/java',
        'windows': 'jdk-{}/bin/java.exe',
        'darwin': 'jdk-{}/bin/java',
    }[platform.system().lower()]
    java = os.path.join(path, 'bin', java.format(version))

    if not os.path.exists(java):
        url = {
            'linux': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_linux-x64_bin.tar.gz',
            'windows': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_windows-x64_bin.zip',
            'darwin': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_osx-x64_bin.tar.gz'
        }[platform.system().lower()]
        url = url.format(version)
        fn = download_file(
            url, path, progress=True)

        unpack_archive(fn, path)
        os.remove(fn)
        if not os.path.exists(java):
            log.error(
                'Java not found even though JDK has been downloaded. Check here %s',
                path
            )
    return java
