import os
from abc import ABCMeta, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from tqdm import tqdm
import magic
import json
import logging
from shutil import unpack_archive, rmtree
from jvd.unpack import unpack, get_archive_type
import gzip
from pathlib import Path

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

    def disassemble(self, file, decompile=False, cleanup=False, cfg=False, no_result=False, file_type=None, as_gzip=False):
        js_file = file + '.asm.json'
        res = None
        log = []
        if os.path.exists(js_file):
            log.append('directly reading the generated json file')
        else:
            try:
                if not file_type:
                    file_type = magic.from_file(file)
                if re.match('(ASCII|UTF-8).+', file_type):
                    js_file = file
                    log.append('directly reading the json file.')
                else:
                    target = file
                    archive_type = get_archive_type(target, file_type)
                    if archive_type:
                        unpack_loc, e_log = unpack(
                            file, file_type=file_type, format=archive_type)
                        log.append(e_log)
                        if unpack_loc is None:
                            return None, log
                        files = [os.path.join(unpack_loc, f)
                                 for f in os.listdir(unpack_loc)]
                        if len(files) > 1:
                            logging.warn('More than one file extracted.')
                        if len(files) > 0:
                            target = files[0]

                    out_js, out_log = self._process(
                        target, file_type, decompile=decompile)

                    res = self.read_result_file(out_js)
                    res['bin']['f_type'] = magic.from_file(target)
                    if cfg:
                        res = self._cfg(res)
                    if not as_gzip:
                        with open(js_file, 'w') as wf:
                            json.dump(res, wf)
                    else:
                        with gzip.GzipFile(js_file+'.gz', 'w') as gf:
                            gf.write(json.dumps(res).encode('utf-8'))
                    if isinstance(log, list):
                        log.extend(log)
                    else:
                        log.append(log)
            except Exception as e:
                log.append(str(e))
                return None, log

        try:
            if not res:
                res = self.read_result_file(js_file)
                if as_gzip and not os.path.exists(js_file + '.gz'):
                    with gzip.GzipFile(js_file+'.gz', 'w') as gf:
                        gf.write(json.dumps(res).encode('utf-8'))
            if no_result:
                return js_file if res else None, '' if res else log
            return res, log
        except Exception as e:
            log.append('Failed ' + file + ' msg: ' + str(e))
            return None, log
        finally:
            try:
                if cleanup:
                    self.cleanup(file)
                if unpack_loc is not None and os.path.exists(unpack_loc):
                    rmtree(unpack_loc)
            except:
                pass

    def disassemble_in_context(self, function_addresses=None, with_ins_comments=True):
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
        with open(file, 'r', encoding='utf-8') as of:
            data = json.load(of)
        return data

    def disassemble_all(
            self,
            path_or_files,
            multiprocessing=True,
            decompile=False,
            cleanup=True,
            cfg=False,
            file_ext='.bin',
            as_gzip=False):
        if isinstance(path_or_files, str):
            logging.info('processing {} with {} '.format(
                path_or_files, file_ext))
            files = [str(p) for p in Path(
                path_or_files).rglob('*') if p.is_file() and p.suffix == file_ext]
        else:
            files = path_or_files

        logging.info('{} files to process'.format(len(files)))

        def gen():
            if multiprocessing:
                with ProcessPoolExecutor(max_workers=50) as e:
                    for ind, extracted in enumerate(
                            e.map(partial(
                                self.disassemble, decompile=decompile,
                                cleanup=cleanup, cfg=cfg, no_result=True, as_gzip=as_gzip), files)):
                        yield ind, extracted
            else:
                for ind, f in enumerate(files):
                    extracted = self.disassemble(
                        f, decompile=decompile, cleanup=cleanup, cfg=cfg, no_result=True,
                        as_gzip=as_gzip)
                    yield ind, extracted

        for ind, extracted in tqdm(gen(), total=len(files)):
            res, log = extracted
            if res is None:
                print(log)
