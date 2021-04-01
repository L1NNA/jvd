from pathlib import Path
import os
import requests
from lxml import html
from tqdm import tqdm
import urllib.request as ur
from zipfile import ZipFile
from jvd.utils import grep_ext, download_file
from jvd.ida.ida import IDA
import sys
import io
from csv import reader as csv_reader
from jvd.resources import ResourceAbstract
from jvd import process_folder
from jvd.utils import download_file, JVSample
from shutil import rmtree
from jvd.labelers import label


files = "https://mb-api.abuse.ch/downloads/"
url_csv = 'https://bazaar.abuse.ch/export/csv/full/'


def _download_all(data_path):
    page = requests.get(files)
    webpage = html.fromstring(page.content)
    links = webpage.xpath('//a/@href')
    links = [(os.path.join(data_path, l), files+l, l)
             for l in links if l.startswith(('2020', '2021'))]
    for l in tqdm(links):
        try:
            _process_entry(l, data_path)

        except Exception as e:
            print(e)
            print(l)
            continue


def _process_entry(entry, data_path):
    file, link, name = entry
    print()
    print('processing', file, name)
    if not os.path.exists(file):
        download_file(link, file, True)
    ext = str(Path(file).with_suffix('')) + '_extracted'
    ext = os.path.abspath(ext)
    if not os.path.exists(ext):
        with ZipFile(file) as zf:
            zf.extractall(ext, pwd=b'infected')

        process_folder(ext, capa=True, unpack=True, disassemble=False)
        _merge_all(data_path)


def _merge_all(path):
    folders = [os.path.join(path, p) for p in os.listdir(path)]
    folders = [f for f in folders if os.path.isdir(f) and f != '_all']
    for f in folders:
        bins = Path(f).rglob('*.bin')
        for b in bins:
            b: Path
            sample = JVSample(str(b))
            family = '-'.join(
                sorted([l for l in sample.labels if not l.startswith('_vt')]))
            if family == 'na':
                dest = os.path.join(path, '_all', 'unknown')
            else:
                dest = os.path.join(path, '_all',
                                    sample.file_type.split()[0].lower() + '.' + family)
            if not os.path.exists(dest):
                os.makedirs(dest)
            os.rename(str(b), os.path.join(dest, b.name))


if __name__ == '__main__':
    _download_all('I:/MalBinZoo/ftp')
    pass
    # label_folder('I:/MalBinZoo/2020-06-29_extracted')
