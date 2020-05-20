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


SRC = os.path.split(os.path.realpath(__file__))[0]
IDA_script = os.path.join(SRC, 'ida_script.py')


class IDA(DisassemblerAbstract):

    def _process(self, file, file_type, decompile=False):
        log = None
        js_file = os.path.join(
            os.path.dirname(file),
            os.path.basename(file) + '.asm.json')
        if not os.path.exists(js_file):
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
            p = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT)
            log, _ = p.communicate()
        return js_file, log

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

    def cleanup(self, file):
        idb_file = file + '.i64'
        if os.path.exists(idb_file):
            try:
                os.remove(idb_file)
            except Exception as e:
                log.error(str(e) + traceback.format_exc())
        idb_file = file + '.idb'
        if os.path.exists(idb_file):
            try:
                os.remove(idb_file)
            except Exception as e:
                log.error(str(e) + traceback.format_exc())
