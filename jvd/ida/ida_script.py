import ida_utils
import json
import codecs
import sys
import os
import idaapi
import idc
import gzip
sys.path.append(os.path.dirname(__file__))

print('jarv1s script for idapro is now running...')
print('Waiting for idapro...')
idaapi.auto_wait()
print('start persisting...')

file_name = os.path.splitext(idc.get_idb_path())[0] + '.asm.json.gz'
output_file = os.getenv('output_file_path', file_name)
include_bytes = os.getenv('include_bytes', False)

data = ida_utils.get_all(with_blocks=True, include_bytes=include_bytes)

content = json.dumps(
    data, ensure_ascii=False
).encode('utf-8')

# with codecs.open(output_file, 'w', encoding='utf-8') as outfile:
#     json.dump(data, outfile, ensure_ascii=False)

with gzip.GzipFile(output_file, 'w') as gf:
    gf.write(content)

idc.qexit(0)
