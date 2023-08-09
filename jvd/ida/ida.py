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
import time
import threading


SRC = os.path.split(os.path.realpath(__file__))[0]
IDA_script = os.path.join(SRC, 'ida_script.py')

ida_available = which('ida64.exe' if platform.system()
                      == 'Windows' else 'ida64') != None

ida64 = 'ida64' if platform.system() == 'Windows' else 'idat64'
ida32 = 'ida' if platform.system() == 'Windows' else 'idat'


class IDA(DisassemblerAbstract):

    def __init__(self):
        pass

    def _process(self, file, file_type, output_file_path, decompile=False, verbose=-1):
        if not ida_available and 'idaapi' not in sys.modules:
            raise FileNotFoundError('IDA is not found!')
        log = None
        program = ida64
        extension = None
        if file_type.startswith('IDA '):
            # 32-bit database
            program = ida32
            extension = '.idb'
        elif file_type.startswith('FoxPro FPT'):
            # 64-bit database
            program = ida64
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
        sub_env["include_bytes"] = ''
        if file.endswith('.idb') or file.endswith('.i64'):
            sub_env["include_bytes"] = 'true'
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

    def context_init(self):
        if 'idaapi' in sys.modules:
            import idaapi
            self.f_current = None

            def _check():
                addr = idaapi.get_screen_ea()
                f_current = idaapi.get_func(addr)
                if f_current and f_current != self.f_current:
                    self.f_current = f_current
                from jvd.client import search
                search(self.context_function_info)

            def _step():
                idaapi.execute_sync(_check, idaapi.MFF_FAST)
                tt = threading.Timer(.5, _step)
                tt.daemon = True
                tt.start()

            _step()
            return True
        return False

    def _get_all_wrapped(self, **kwargs):
        from jvd.ida.ida_utils import get_all
        import idaapi
        # this import cannot be moved to the header since it can
        # be only imported when running in context
        _bin = {}

        def _get():
            _bin.update(get_all(**kwargs))

        idaapi.execute_sync(_get, idaapi.MFF_FAST)

        return _bin

    def context_binary_info(self):
        _bin_info = self._get_all_wrapped(
            function_eas=None,
            with_blocks=False)['bin']
        return {
            k: v for k, v in _bin_info.items() if k not in ['strings', 'data', ]
        }

    def context_function_info(self):
        _all_info = self._get_all_wrapped(
            function_eas=None,
            with_blocks=True,
            current_ea=True
        )

        refs = set()
        for b in _all_info['blocks']:
            for i in b.get('ins', []):
                for r in i.get('dr', []) + i.get('cr', []):
                    refs.add(r)

        _cleaned_bin = {
            k: v for k, v in _all_info['bin'].items() if k not in [
                'strings', 'data', 'import_functions', 'export_functions',
                'import_modules', 'seg', 'entry_points']
        }
        _cleaned_bin['strings'] = {
            k: v for k, v in _all_info['bin']['strings'].items() if k in refs
        }
        _cleaned_bin['data'] = {
            k: v for k, v in _all_info['bin']['strings'].items() if k in refs
        }
        return {
            'bin': _cleaned_bin,
            'functions': _all_info['functions'],
            'blocks': _all_info['blocks'],
            'comments': _all_info['comments'],
        }
