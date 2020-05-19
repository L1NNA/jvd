import os
from abc import ABCMeta, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from tqdm import tqdm
import magic
import json
import logging

import re


class DisassemblerAbstract(metaclass=ABCMeta):

    @abstractmethod
    def _process(self, file, file_type, decompile=False):
        pass

    def _cfg(self, res):
        blk2ind = {b['_id']: ind
                   for ind, b in enumerate(res['blocks'])}
        adj_sp = [(blk2ind[b['_id']], blk2ind[c])
                  for b in res['blocks'] for c in b['calls'] if c in blk2ind]
        res['cfg'] = adj_sp
        return res

    def disassemble(self, file, decompile=False, cleanup=False, cfg=False):
        file_type = magic.from_file(file)
        res = None
        log = []
        if re.match('(ASCII|UTF-8).+', file_type):
            js_file = file
            log = ['directly reading generated json file.']
        else:
            js_file, log = self._process(
                file, file_type, decompile=decompile)
            if not isinstance(log, list):
                log = [log]
        try:
            res = self.read_result_file(js_file)
            if cfg:
                res = self._cfg(res)
                with open(js_file, 'w') as wf:
                    json.dump(res, wf)
            return res, log
        except Exception as e:
            log.append('Failed ' + file + ' msg: ' + str(e))
            return None, log
        finally:
            try:
                if cleanup:
                    self.cleanup(file)
            except:
                pass

    def disassemble_in_context(self, with_ins_comments=True):
        """
        Call within the disassembler context e.g. as a plugin (so no need to call another process)
        There is no `file` argument as this function is expected to with the file open on a given disassembler.

        with_ins_comments controls if the return result should include all the instructions and comments.
        """
        return None
    

    def sync_comments(self, to_be_updates=None, to_be_deleted=None):
        pass
    

    def jump(self, address):
        pass


    @abstractmethod
    def cleanup(self, file):
        pass

    def read_result_file(self, file):
        with open(file) as of:
            data = json.load(of)
        return data

    def disassemble_all(
            self,
            path_or_files,
            multiprocessing=True,
            decompile=False,
            cleanup=True,
            cfg=False,
            file_ext='.bin'):
        if isinstance(path_or_files, str):
            logging.info('processing {} with {} '.format(
                path_or_files, file_ext))
            files = [os.path.join(path_or_files, f) for f in os.listdir(
                path_or_files) if f.endswith(file_ext)]
        else:
            path_or_files = [path_or_files]

        logging.info('{} files to process'.format(len(files)))

        def gen():
            if multiprocessing:
                with ProcessPoolExecutor(max_workers=30) as e:
                    for ind, extracted in enumerate(
                            e.map(partial(
                                self.disassemble, decompile=decompile,
                                cleanup=cleanup, cfg=cfg), files)):
                        yield ind, extracted
            else:
                for ind, f in enumerate(files):
                    extracted = self.disassemble(
                        f, decompile=decompile, cleanup=cleanup, cfg=cfg)
                    yield ind, extracted

        for ind, extracted in tqdm(gen(), total=len(files)):
            res, log = extracted
            if res is None:
                print(log)
