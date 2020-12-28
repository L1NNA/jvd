import logging as log
import os
import platform
import urllib
from abc import ABCMeta, abstractmethod
from datetime import datetime
from pathlib import Path
from shutil import rmtree, unpack_archive

import pytz
from dateutil.tz import tzlocal

from jvd.utils import download_file, fn_from_url


class ResourceAbstract(metaclass=ABCMeta):

    home = os.path.join(str(Path.home()), 'jv-dependencies')

    def __init__(self):
        super().__init__()
        self.linux = None
        self.windows = None
        self.darwin = None
        self.default = None
        self.unpack = False
        self.check_update = False

    def get(self):
        url = getattr(self, platform.system().lower())
        url = self.default if not url else url
        return self._download(url, show_progress=True, unpack_if_needed=True)

    def _download(self, url, show_progress, unpack_if_needed, home=None):
        if home is None:
            home = self.home
        folder = os.path.join(
            home, self.__class__.__name__.lower(),
        )
        if not os.path.exists(folder):
            os.makedirs(folder)
        file = fn_from_url(url)
        file = os.path.join(
            folder, file)
        # file_unpack = os.path.join(folder, "unpacked")
        file_unpack = file + '_unpacked'

        download = not os.path.exists(file)
        if not download and self.check_update:
            try:
                u = urllib.request.urlopen(url)
                meta = u.info()
                url_time = meta['Last-Modified']
                url_date = datetime.strptime(
                    url_time, "%a, %d %b %Y %X GMT")
                url_date = pytz.utc.localize(url_date)
                file_time = datetime.fromtimestamp(
                    os.path.getmtime(file), tz=tzlocal())

                if url_date > file_time:
                    log.info(
                        'File exists but the server has a newer version. {} vs {}'.format(
                            url_date, file_time))
                    download = True
                else:
                    download = False
            except Exception as e:
                log.warn('Library {} would like to check for updates but failed'.format(
                    str(e)
                ))

        if download:
            if os.path.exists(file):
                os.remove(file)
            if os.path.exists(file_unpack):
                rmtree(file_unpack)
            download_file(url, file, show_progress)

        if self.unpack and unpack_if_needed:
            if not os.path.exists(file_unpack):
                unpack_archive(file, file_unpack)
            return file_unpack
        else:
            return file

    def cache(self, root):
        if self.windows:
            self._download(
                self.windows, show_progress=True,
                unpack_if_needed=False, home=root)
        if self.linux:
            self._download(
                self.linux, show_progress=True,
                unpack_if_needed=False, home=root)
        if self.darwin:
            self._download(
                self.darwin, show_progress=True,
                unpack_if_needed=False, home=root)
        if self.default:
            self._download(
                self.default, show_progress=True,
                unpack_if_needed=False, home=root)


def cache_all(root=ResourceAbstract.home):
    for res in ResourceAbstract.__subclasses__():
        res = res().cache(root)


def require(library):
    for res in ResourceAbstract.__subclasses__():
        if res.__name__.lower() == library.lower():
            res = res()
            return res.get()
