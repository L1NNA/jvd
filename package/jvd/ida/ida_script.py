import json
import codecs
import sys
import os
import idaapi
import idc
sys.path.append(os.path.dirname(__file__))
import ida_utils

print('jarv1s script for idapro is now running...')
print('Waiting for idapro...')
idaapi.auto_wait()
print('start persisting...')

data = ida_utils.get_all(with_blocks=True)
file_name = os.path.splitext(idc.get_idb_path())[0]

with codecs.open(file_name + '.asm.json', 'w', encoding='utf-8') as outfile:
    json.dump(data, outfile, ensure_ascii=False)

idc.qexit(0)
