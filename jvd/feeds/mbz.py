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
from jvd.utils import download_file


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
            _process_entry(l)
        except Exception as e:
            print(e)
            print(l)
            continue


def _process_entry(entry):
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

        process_folder(ext, True)


if __name__ == '__main__':
    _download_all('I:/MalBinZoo/ftp')
    pass
    # label_folder('I:/MalBinZoo/2020-06-29_extracted')
