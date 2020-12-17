import gzip
import json
import logging
import os
import re
from abc import ABCMeta, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from shutil import rmtree, unpack_archive
import tempfile
from shutil import copyfile, rmtree

import magic
from tqdm import tqdm

from jvd.utils import read_gz_js


class DisassemblerAbstract(metaclass=ABCMeta):

    @abstractmethod
    def _process(self, file, file_type, output_file_path, decompile=False):
        pass

    def _cfg(self, res):
        blk2ind = {b['_id']: ind
                   for ind, b in enumerate(res['blocks'])}
        adj_sp = [(blk2ind[b['_id']], blk2ind[c])
                  for b in res['blocks'] for c in b['calls'] if c in blk2ind]
        res['cfg'] = adj_sp
        return res

    def disassemble(self, file, decompile=False, cleanup=False, cfg=False, no_result=False, file_type=None):
        js_file = file + '.asm.json.gz'
        res = None
        log = []
        file_type = file_type if file_type else magic.from_file(file)
        if os.path.exists(js_file):
            log.append('directly reading the generated json file')
        else:
            tmp_folder = file + '.tmp'
            try:
                os.mkdir(tmp_folder)
                new_file = os.path.join(tmp_folder, os.path.basename(file))
                new_file_js = os.path.join(
                    tmp_folder, os.path.basename(js_file))
                copyfile(file, new_file)
                _, out_log = self._process(
                    new_file, file_type, output_file_path=new_file_js, decompile=decompile)
                copyfile(new_file_js, js_file)
                if isinstance(log, list):
                    log.extend(log)
                else:
                    log.append(str(log))
            except Exception as e:
                log.append(str(e))
                return None, log
            finally:
                rmtree(tmp_folder)

        try:
            res = read_gz_js(js_file)
            changed = False
            if 'f_type' not in res:
                res['bin']['f_type'] = file_type
                changed = True
            if cfg and 'cfg' not in res:
                self._cfg(res)
                changed = True
            if changed:
                with gzip.GzipFile(js_file, 'w') as gf:
                    gf.write(json.dumps(res).encode('utf-8'))
            if no_result:
                return js_file if res else None, log
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
                                cleanup=cleanup, cfg=cfg, no_result=True), files)):
                        yield ind, extracted
            else:
                for ind, f in enumerate(files):
                    extracted = self.disassemble(
                        f, decompile=decompile, cleanup=cleanup, cfg=cfg, no_result=True,)
                    yield ind, extracted

        for ind, extracted in tqdm(gen(), total=len(files)):
            res, log = extracted
            if res is None:
                print(log)
