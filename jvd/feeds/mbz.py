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


def _download_all(data_path):
    page = requests.get(files)
    webpage = html.fromstring(page.content)
    links = webpage.xpath('//a/@href')
    links = [(os.path.join(data_path, l), files+l, l)
             for l in links if l.startswith(('2020', '2021'))]
    for l in tqdm(links):
        try:
            _process_entry(l)
        except Exception as e:
            print(e)
            print(l)
            continue


def _process_entry(entry):
    file, link, name = entry
    if not os.path.exists(file):
        ur.urlretrieve(link, file)
    ext = str(Path(file).with_suffix('')) + '_extracted'
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


if __name__ == '__main__':
    _download_all('I:/MalBinZoo/ftp')
