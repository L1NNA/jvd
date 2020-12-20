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
import datetime
import pytz
from dateutil.tz import tzlocal
from jvd.utils import download_file


def install_jar_if_needed(path, v='v0.0.1'):
    url = 'https://github.com/L1NNA/JARV1S-Ghidra/releases/download/{}/jarv1s-ghidra.jar'.format(
        v)
    jar = os.path.join(path, 'jarv1s-ghidra.jar')
    download = True
    if os.path.exists(jar):
        u = urllib.request.urlopen(url)
        meta = u.info()
        url_time = meta['Last-Modified']
        url_date = datetime.datetime.strptime(
            url_time, "%a, %d %b %Y %X GMT")
        url_date = pytz.utc.localize(url_date)
        file_time = datetime.datetime.fromtimestamp(
            os.path.getmtime(jar), tz=tzlocal())

        if url_date > file_time:
            log.info('Jar file exists but the server has a newer version. {} vs {}'.format(
                url_date, file_time))
            os.remove(jar)
            download = True
        else:
            download = False

    if download:
        log.info('Dowloading pre-built jar into {}'.format(path))
        download_file(
            url, path, progress=True)
    if not os.path.exists(jar):
        log.error('Jar downloaded to {} but still not found'.format(path))
    return jar


def install_jdk_if_needed(path, jdk='13.0.1'):
    val = None
    try:
        version = subprocess.check_output(
            ['java', '-version'], stderr=subprocess.STDOUT)
        pattern = b'\"(\d+[\.]*\d+).*\"'
        val = re.search(pattern, version).groups()[0]
        val = float(val)
        if val >= 11:
            return 'java'
    except Exception as e:
        pass

    if not os.path.exists(path):
        os.mkdir(path)

    java = {
        'linux': 'jdk-{}/bin/java',
        'windows': 'jdk-{}/bin/java.exe',
        'darwin': 'jdk-{}.jdk/contents/home/bin/java',
    }[platform.system().lower()]
    java = os.path.join(path, java.format(jdk))

    if not os.path.exists(java):
        url = {
            'linux': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_linux-x64_bin.tar.gz',
            'windows': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_windows-x64_bin.zip',
            'darwin': 'https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-{}_osx-x64_bin.tar.gz'
        }[platform.system().lower()]
        url = url.format(jdk)
        if val:
            log.info(
                'Current version of java is {} (not supported by Ghidra).'.format(val))
        log.info('Downloading OpenJDK to {}'.format(url, path))
        fn = download_file(
            url, path, progress=True)

        unpack_archive(fn, path)
        os.remove(fn)
        if not os.path.exists(java):
            log.error(
                'Java not found even though JDK has been downloaded. Check here %s',
                path
            )
    log.info('using: %s', java)
    return java
