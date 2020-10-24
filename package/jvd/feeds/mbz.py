from pathlib import Path
import os
import requests
from lxml import html
from tqdm import tqdm
import urllib.request as ur
from zipfile import ZipFile
from jvd.ida.ida import IDA
import sys


files = "https://mb-api.abuse.ch/downloads/"


def _process_all(data_path, since):
    ext = os.path.join(data_path, 'extracted')
    page = requests.get(files)
    webpage = html.fromstring(page.content)
    links = webpage.xpath('//a/@href')
    links = [(os.path.join(data_path, l), files+l, l)
             for l in links if l.startswith('2020')]
    for i in range(len(links)):
        if since in links[i][2]:
            break
    links = links[i:]
    for l in tqdm(links):
        try:
            _process_entry(l, ext)
        except Exception as e:
            print(e)
            print(l)
            continue

    _ren_dis_entry(ext)
    _disassemble_all(ext)


def _process_entry(entry, ext):
    file, link, name = entry
    if not os.path.exists(file):
        ur.urlretrieve(link, file)
    ext = os.path.abspath(ext)
    with ZipFile(file) as zf:
        zf.extractall(ext, pwd=b'infected')


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
        path, cfg=False, as_gzip=True
    )


def _cleanup_all(ext):
    for bin_file in os.listdir(ext):
        bin_file = os.path.join(ext, bin_file)
        ext = Path(bin_file).suffix
        if ext in ['i64', 'id0', 'id1', 'id2', 'til', 'nam', 'json', '']:
            os.remove(bin_file)


if __name__ == '__main__':
    _process_all('I:\MalBinZoo', sys.argv[1])
