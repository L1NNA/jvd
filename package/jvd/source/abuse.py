import requests
import os
from bs4 import BeautifulSoup
from lxml import html
import requests
from tqdm import tqdm
import urllib.request as ur
from zipfile import ZipFile


files = "https://mb-api.abuse.ch/downloads/"


# download files
page = requests.get(files)
webpage = html.fromstring(page.content)
links = webpage.xpath('//a/@href')
links = [(os.path.join(path, l),files+l) for l in links if l.startswith('2020')]

for i, (f,l) in enumerate(links):
    if not os.path.exists(f):
        print('retrieving {}/{} {}'.format(i, len(links), l))
        ur.urlretrieve (l, f)
        with ZipFile(f) as zf:
            ext = 'tmp'
            zf.extractall(ext, pwd=b'infected')
