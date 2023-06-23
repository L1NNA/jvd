import gzip
import json
import logging
import os
import re
import tempfile
from abc import ABCMeta, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from shutil import copyfile, rmtree, unpack_archive

from tqdm import tqdm

from jvd.utils import read_gz_js, write_gz_js, get_file_type, grep_ext, m_map


class DisassemblerAbstract(metaclass=ABCMeta):
    timeout = 24*60*60

    @abstractmethod
    def _process(self, file, file_type, output_file_path, decompile=False, verobse=-1):
        pass

    def _cfg(self, res):
        blk2ind = {b['addr_start']: ind
                   for ind, b in enumerate(res['blocks'])}
        adj_sp = [(blk2ind[b['addr_start']], blk2ind[c])
                  for b in res['blocks'] for c in b['calls'] if c in blk2ind]
        res['cfg'] = adj_sp
        return res

    def disassemble(
            self, file, decompile=False, cleanup=False,
        file_type=None, capa=False, verbose=-1,
            additional_ext=''):
        js_file = file + '{}.asm.json.gz'.format(additional_ext)
        log = []
        file_type = file_type if file_type else get_file_type(file)
        if os.path.exists(js_file):
            log.append('directly reading the generated json file')
            if not capa:
                return js_file, log
        else:
            tmp_folder = file + '{}.tmp'.format(additional_ext)
            out_log = None
            try:
                if os.path.exists(tmp_folder):
                    rmtree(tmp_folder)
                os.mkdir(tmp_folder)
                new_file = os.path.join(tmp_folder, os.path.basename(file))
                new_file_js = os.path.join(
                    tmp_folder, os.path.basename(js_file))
                copyfile(file, new_file)
                _, out_log = self._process(
                    new_file, file_type, output_file_path=new_file_js, decompile=decompile,
                    verbose=verbose)
                copyfile(new_file_js, js_file)
                if isinstance(log, list):
                    log.extend(log)
                else:
                    log.append(str(log))
            except Exception as e:
                log.append(str(e))
                if verbose > 1:
                    raise e
                return None, log
            finally:
                try:
                    rmtree(tmp_folder)
                except:
                    pass
                pass

        try:
            res = read_gz_js(js_file)
            if len(res['blocks']) < 1:
                if os.path.exists(js_file):
                    os.remove(js_file)
                raise Exception('no basic blocks are generated.. skipping.')
            if capa and 'capa' not in res:
                from jvd.capa.extractor import capa_analyze, CapaJsonObjectEncoder
                res['capa'] = capa_analyze(res, file, verbose=verbose)
                content = json.dumps(
                    res,
                    cls=CapaJsonObjectEncoder,
                ).encode('utf-8')
                with gzip.GzipFile(js_file, 'w') as gf:
                    gf.write(content)
            return js_file, log
        except Exception as e:
            log.append('Failed ' + file + ' msg: ' + str(e))
            if verbose > 1:
                print(log)
                raise e
            return None, log
        finally:
            try:
                if cleanup:
                    self.cleanup(file)
            except:
                pass

    # def disassemble_in_context(self, function_addresses=None, with_ins_comments=True):
    #     """
    #     Call within the disassembler context e.g. as a plugin (so no need to call another process)
    #     There is no `file` argument as this function is expected to with the file open on a given disassembler.

    #     with_ins_comments controls if the return result should include all the instructions and comments.
    #     """
    #     return None

    def context_init(self):
        return False

    def context_binary_info(self):
        pass

    def context_function_info(self):
        pass

    def cleanup(self, file):
        js_file = file + '.asm.json.gz'
        if os.path.exists(js_file):
            os.remove(js_file)
        pass

    def disassemble_all(
            self,
            path_or_files,
            multiprocessing=True,
            decompile=False,
            cleanup=False,
            cfg=False,
            file_ext='.bin',
            capa=False,
            verbose=-1):
        if isinstance(path_or_files, str):
            logging.info('processing {} with {} '.format(
                path_or_files, file_ext))
            files = grep_ext(path_or_files, ext=file_ext)
        else:
            files = path_or_files

        logging.info('{} files to process'.format(len(files)))

        def gen():
            if multiprocessing:
                yield from m_map(
                    partial(
                        self.disassemble, decompile=decompile,
                        cleanup=cleanup, cfg=cfg, no_result=True,
                        capa=capa, verbose=verbose), files
                )
                with ProcessPoolExecutor(max_workers=50) as e:
                    for ind, extracted in enumerate(
                            e.map()):
                        yield ind, extracted
            else:
                for ind, f in enumerate(files):
                    extracted = self.disassemble(
                        f, decompile=decompile, cleanup=cleanup, cfg=cfg,
                        no_result=True, capa=capa, verbose=verbose)
                    yield ind, extracted

        for ind, extracted in tqdm(gen(), total=len(files)):
            res, log = extracted
            if res is None:
                print(log)
