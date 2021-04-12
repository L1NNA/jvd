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
from jvd.utils import download_file, JVSample, read_gz_js, write_gz_js
from shutil import rmtree
from jvd.labelers import label


files = "https://mb-api.abuse.ch/downloads/"
url_csv = 'https://bazaar.abuse.ch/export/csv/full/'


def _download_all(data_path):
    cache = os.path.join(data_path, 'progress.json.gz')
    if not os.path.exists(cache):
        write_gz_js({'done': []}, cache)
    done = set(read_gz_js(cache)['done'])

    page = requests.get(files)
    webpage = html.fromstring(page.content)
    links = webpage.xpath('//a/@href')
    links = [(os.path.join(data_path, l), files+l, l)
             for l in links if l.startswith(('2020', '2021'))]
    for l in tqdm(links):
        try:
            # _process_entry(l, data_path, done)
            file, link, name = l
            print()
            print('processing', file, name)
            if not os.path.exists(file):
                download_file(link, file, True)
            ext = str(Path(file).with_suffix('')) + '_extracted'
            ext = os.path.abspath(ext)
            if not os.path.exists(ext) and os.path.basename(ext) not in done:
                with ZipFile(file) as zf:
                    zf.extractall(ext, pwd=b'infected')

                process_folder(ext, capa=True, unpack=True, disassemble=False)
                _merge_all(data_path)
            done.add(os.path.basename(ext))
            write_gz_js({'done': list(done)}, cache)

        except Exception as e:
            print(e)
            print(l)
            continue
    _merge_all(data_path)


def _merge_all(path, out_dir='_all_staging'):
    folders = [os.path.join(path, p) for p in os.listdir(path)]
    folders = [f for f in folders if os.path.isdir(
        f) and not os.path.basename(f).startswith('_all')]
    print(folders)
    for f in tqdm(folders):
        bins = Path(f).rglob('*.bin')
        for b in tqdm(bins):
            b: Path
            sample = JVSample(str(b))
            family = '-'.join(
                sorted([l for l in sample.labels if not l.startswith('_vt')]))
            if family == 'na':
                dest = os.path.join(path, out_dir, 'unknown')
            else:
                dest = os.path.join(path, out_dir, sample.file_type.split()[0].lower(),
                                    sample.file_type.split()[0].lower() + '.' + family)
            if not os.path.exists(dest):
                os.makedirs(dest)
            target = os.path.join(dest, b.name)
            if not os.path.exists(target):
                os.rename(str(b), target)


if __name__ == '__main__':
    data_path = 'I:/MalBinZoo/ftp'
    _download_all(data_path)
    _merge_all(data_path)
    pass
    # label_folder('I:/MalBinZoo/2020-06-29_extracted')
