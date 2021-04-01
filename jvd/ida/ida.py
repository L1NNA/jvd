import sys
import os
import json
import hashlib
import logging
import base64
import shutil
from concurrent.futures import ProcessPoolExecutor
from subprocess import Popen, PIPE, STDOUT
from jvd.disassembler import DisassemblerAbstract
import logging as log
import traceback
from jvd.utils import read_gz_js, write_gz_js, which, check_output_ctx
import platform
from jvd.resources import require


SRC = os.path.split(os.path.realpath(__file__))[0]
IDA_script = os.path.join(SRC, 'ida_script.py')

ida_available = which('ida64.exe' if platform.system()
                      == 'Windows' else 'ida64') != None


class IDA(DisassemblerAbstract):

    def __init__(self):
        if not ida_available:
            raise FileNotFoundError('IDA is not found!')

    def _process(self, file, file_type, output_file_path, decompile=False, verbose=-1):
        log = None
        program = 'ida64'
        extension = None
        if file_type.startswith('IDA '):
            # 32-bit database
            program = 'ida'
            extension = '.idb'
        elif file_type.startswith('FoxPro FPT'):
            # 64-bit database
            program = 'ida64'
            extension = '.i64'
        if extension:
            db = file + extension
            if not os.path.exists(db):
                shutil.copyfile(file, db)
            file = db
        cmd = [program, '-A', '-S{}'.format(IDA_script), file]
        # print(cmd)
        sub_env = os.environ.copy()
        sub_env["output_file_path"] = os.path.abspath(output_file_path)
        # print(cmd)
        # p = Popen(
        #     cmd,
        #     env=sub_env,
        #     stdout=PIPE,
        #     stderr=STDOUT)
        # log, _ = p.communicate(timeout=self.timeout)
        if verbose > 1:
            print(' '.join(cmd))
        with check_output_ctx(cmd, timeout=self.timeout, env=sub_env) as log:
            if not log:
                log = ''

        if decompile:
            # assuming that IDA does not support decompilation
            # transfer decompiled code to IDA
            jar = require('ghidrajar')
            java = require('jdk')
            from jvd.ghidra.decompiler import process as gh_process
            obj = read_gz_js(output_file_path)
            func_entries = [f['addr_start']-obj['bin']['base']
                            for f in obj['functions']]

            output_file_path_gh = output_file_path + '.gh.gz'
            gh_process(java, jar, file, output_file_path_gh,
                       decompile=True, func_entries=func_entries)
            if os.path.exists(output_file_path_gh):
                obj_gh = read_gz_js(output_file_path_gh)

            src = obj_gh['functions_src']
            base_diff = obj_gh['bin']['base'] - obj['bin']['base']
            for f in src:
                f['addr_start'] = f['addr_start'] - base_diff
            obj['functions_src'] = src
            write_gz_js(obj, output_file_path)

        return output_file_path, log

    def disassemble_in_context(self, function_addresses=None, with_ins_comments=True):
        from jvd.ida.ida_utils import get_all
        import idaapi
        # this import cannot be moved to the header since it can
        # be only imported when running in context
        res = {}

        def _get():
            res.update(get_all(function_eas=function_addresses,
                               with_blocks=with_ins_comments))

        idaapi.execute_sync(_get, idaapi.MFF_FAST)
        return res
