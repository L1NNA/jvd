import json
import logging as log
from pathlib import Path
import tempfile
from tqdm import tqdm
import subprocess
from jvd.resources import ResourceAbstract, require
import re
import platform
import os

from jvd.utils import check_output_ctx


class StylomatrixJar(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.default = 'https://github.com/L1NNA/Authorship-StyloMatrix/releases/download/v0.0.1/authorship-0.0.1-SNAPSHOT-jar-with-dependencies.jar'
        self.check_update = True


class NLPResource(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.default = 'https://github.com/L1NNA/Authorship-StyloMatrix/releases/download/v0.0.1/nlps.zip'
        self.unpack = True

    def get(self):
        return super().get() + '/nlps'


def __load_embedding(js_file, size):
    js_file = Path(js_file)
    if not js_file.exists():
        log.error(f'missing {js_file.name} embedding produced...')
        return {}
    else:
        obj = json.load(open(js_file))
        res = {}
        for k, m in obj.items():
            m = {
                int(k.replace('.txt', '').replace('train_', '').replace('test_', '')): v
                for k, v in m.items()}
            if len(m) < 1:
                res[k] = []
            else:
                res[k] = [obj.get(i, []) for i in range(size)]
        return res


methods = ['char2vec', 'tl2vec', 'pos2vec', 'stylometric']


def extract_embedding(training_documents, testing_documents, method):
    jar = require('StylomatrixJar')
    nlp = require('NLPResource')
    java = require('jdk')
    j_class = 'ca.mcgill.sis.dmas.nlp.exp.GeneralText'

    with tempfile.TemporaryDirectory() as tmpdirname:
        root = Path(tmpdirname)
        root_train = root.joinpath('train')
        root_test = root.joinpath('test')
        root_train.mkdir()
        root_test.mkdir()

        for i, t in enumerate(training_documents):
            open(root_train.joinpath(f'{i}.txt'), 'w').write(t)
        for i, t in enumerate(testing_documents):
            open(root_test.joinpath(f'{i}.txt'), 'w').write(t)

        cmd = [java, '-cp', jar, j_class, tmpdirname, method, nlp]
        e_train = []
        e_test = []
        with check_output_ctx(cmd, live=True):
            e_train = __load_embedding(
                root.joinpath('e_train.json'), len(training_documents))
            e_test = __load_embedding(
                root.joinpath('e_test.json'), len(testing_documents))
        return e_train, e_test
