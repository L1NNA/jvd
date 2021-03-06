from zipfile import ZipFile
from jvd.utils import download_file, JVSample
from csv import reader as csv_reader
from jvd.resources import ResourceAbstract
import logging as log
import os


class Labeler:
    def label(self, sample):
        return []


class MBZLabeler(ResourceAbstract, Labeler):
    def __init__(self):
        super().__init__()
        self.default = 'https://bazaar.abuse.ch/export/csv/full/'
        self.check_update = True
        self.unpack = True
        self.signatures = None

    def get(self):
        file = self._download(
            self.default, show_progress=True, unpack_if_needed=True, file='all.zip')
        with open(os.path.join(file, 'full.csv'), 'rb') as rf:
            csv = rf.read().decode('utf8').splitlines()
            signatures = {}
            for row in csv_reader(filter(
                lambda x: x.strip()[0] != '#', csv
            ), quotechar='"', skipinitialspace=True, delimiter=',', escapechar='\\'):
                # sha256 & signatures
                if len(row[8]) < 0 or row[8] == 'n/a' or row[10] == 'n/a':
                    continue
                sig = row[8].strip().lower()
                av = int(float(row[10]))
                signatures[row[1]] = [sig, f'av{av}']
        self.signatures = signatures
        return signatures

    def label(self, hash):
        if not self.signatures:
            self.signatures = self.get()
        if hash not in self.signatures:
            return None
        else:
            return self.signatures.get(hash)


all_labelers = [c() for c in Labeler.__subclasses__()]


def label(sample: JVSample):
    for up in all_labelers:
        up: Labeler
        sample_labels = up.label(sample.get_sha256())
        resource_labels = up.label(sample.resource)
        if sample_labels:
            for s in sample_labels:
                sample.add_label(s)
        if resource_labels:
            for s in resource_labels:
                sample.add_label(s)
    sample.save()
