# *******************************************************************************
#  * Copyright 2017 McGill University All rights reserved.
#  *
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  *     http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
#  *******************************************************************************/

from re import sub
from datetime import datetime
import codecs
import hashlib
import os
import ida_nalt
import idc
import idautils
import idaapi
import json
from collections import defaultdict
import sys
py_version = sys.version_info[0]
if py_version == 2:
    from sets import Set as set


now_str = datetime.now().isoformat()

print('jarv1s script for idapro is now running...')
print('Waiting for idapro...')
idaapi.auto_wait()
print('start persisting...')


def _iter_extra_comments(ea, start):
    end = idaapi.get_first_free_extra_cmtidx(ea, start)
    lines = [idaapi.get_extra_cmt(ea, idx) for idx in
             range(start, end)]
    lines = [line if line else '' for line in lines]
    return "\n".join(lines)


def get_comments(binary_id, function_id, block_id, ea):
    comments = []
    text = idc.get_cmt(ea, 1)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'repeatable',
                         'content': text, 'address': ea, 'created_at': now_str})
    text = idc.get_cmt(ea, 0)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'regular',
                         'content': text, 'address': ea, 'created_at': now_str})
    text = _iter_extra_comments(ea, idaapi.E_PREV)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'anterior',
                         'content': text, 'address': ea, 'created_at': now_str})
    text = _iter_extra_comments(ea, idaapi.E_NEXT)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'posterior',
                         'content': text, 'address': ea, 'created_at': now_str})
    return comments


def get_apis(func_addr):
    calls = 0
    apis = []
    flags = get_func_attr(func_addr, FUNCATTR_FLAGS)
    # ignore library functions
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        return calls, apis
    # list of addresses
    dism_addr = list(FuncItems(func_addr))
    for instr in dism_addr:
        tmp_api_address = ""
        if idaapi.is_call_insn(instr):
            # In theory an API address should only have one xrefs
            # The xrefs approach was used because I could not find how to
            # get the API name by address.
            for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                if xref.to is None:
                    calls += 1
                    continue
                tmp_api_address = xref.to
                break
            # get next instr since api address could not be found
            if tmp_api_address == "":
                calls += 1
                continue
            api_flags = get_func_attr(tmp_api_address, FUNCATTR_FLAGS)
            # check for lib code (api)
            if api_flags & idaapi.FUNC_LIB == True or api_flags & idaapi.FUNC_THUNK:
                tmp_api_name = get_name(
                    tmp_api_address, ida_name.GN_VISIBLE | calc_gtn_flags(0, tmp_api_address))
                if tmp_api_name:
                    apis.append(tmp_api_name)
            else:
                calls += 1
    return calls, apis


exports = {e[1] for e in idautils.Entries()}
tkn_skips = ('::', 'libname', 'j_')


def isLibrary(fn):
    fn = idaapi.get_func(fn)
    if fn is None:
        return True
    name = idc.GetFunctionName(fn.startEA)
    for x in tkn_skips:
        if x in name:
            return True
    return fn.flags & idaapi.FUNC_LIB == idaapi.FUNC_LIB


def tooShort(fc):
    if fc.size > 1:
        return False
    if fc.size < 1:
        return True
    hds = [h for h in Heads(fc[0].startEA, fc[0].endEA)]
    return len(hds) < 3


def no_callers(fn_ea):
    fea = idc.GetFunctionAttr(fn_ea, idc.FUNCATTR_START)
    if fea in exports:
        return False
    if len(list(idautils.CodeRefsTo(fea, 1))) < 1:
        return True
    return False


rebase = int(os.getenv('K_REBASE', 0))
cleanStack = int(os.getenv('K_CLEANSTACK', 0))
if rebase == 1:
    idaapi.rebase_program(-1 * idaapi.get_imagebase(), 0)

file_name = os.path.splitext(idc.get_idb_path())[0]
binary_name = idaapi.get_input_file_path()
print(binary_name)
binary = dict()
binary['name'] = binary_name
sha256 = ida_nalt.retrieve_input_file_sha256()
if sha256 is None:
    sha256 = idautils.GetInputFileMD5()
sha256 = sha256.lower()
if py_version == 3:
    sha256 = sha256.hex()
binary['_id'] = sha256

info = idaapi.get_inf_structure()
bits = "b32"
endian = "be"
processor = info.procName.lower()
if idaapi.cvar.inf.version >= 700:
    endian = "be" if idaapi.cvar.inf.is_be() else "le"
else:
    endian = "be" if idaapi.cvar.inf.mf else "le"
if info.is_32bit():
    bits = "b32"
if info.is_64bit():
    bits = "b64"
if processor.startswith('mips'):
    processor = 'mips'

# binary['architecture'] = "{}-{}-{}".format(processor, bits, endian)
binary['architecture'] = processor
binary['endian'] = endian
binary['bits'] = bits
binary['disassembler'] = 'ida'
binary['compiler'] = idaapi.get_compiler_name(info.cc.id)
binary['description'] = ""


functions = {}
blocks = {}
for seg_ea in Segments():
    for function_ea in Functions(get_segm_start(seg_ea), get_segm_end(seg_ea)):
        m = hashlib.sha256()
        m.update(sha256.encode())
        m.update('f'.encode())
        m.update(str(function_ea).encode())

        f_name = get_func_name(function_ea)
        function = dict()
        function['_id'] = m.hexdigest()
        function['name'] = f_name
        function['description'] = ''
        function['addr_start'] = function_ea
        function['addr_end'] = find_func_end(function_ea)
        function['bin_id'] = sha256
        function['api'] = get_apis(function_ea)[1]
        function['calls'] = []
        functions[function_ea] = function
        func_blocks = list(idaapi.FlowChart(idaapi.get_func(function_ea)))
        function['bbs_len'] = len(func_blocks)

        for bblock in func_blocks:

            m = hashlib.sha256()
            m.update(sha256.encode())
            m.update('b'.encode())
            m.update(str(bblock.start_ea).encode())

            sblock = dict()
            sblock['_id'] = m.hexdigest()
            sblock['addr_start'] = bblock.start_ea
            if processor == 'arm':
                sblock['addr_start'] += GetReg(bblock.start_ea, 'T')
            sblock['addr_end'] = bblock.end_ea
            sblock['name'] = 'loc_' + format(bblock.start_ea, 'x').upper()
            sblock['ins'] = []
            sblock['bin_id'] = sha256
            sblock['func_id'] = function['_id']
            sblock['calls'] = []
            blocks[bblock.start_ea] = sblock

callees = defaultdict(set)
for seg_ea in Segments():
    for function_ea in Functions(get_segm_start(seg_ea), get_segm_end(seg_ea)):
        for ref_ea in CodeRefsTo(function_ea, 0):
            if ref_ea in functions:
                functions[function_ea]['calls'].append(
                    functions[ref_ea]['_id'])


if py_version == 2:
    binary['strings'] = {st.ea: sub(r"\s+", '-', str(st).strip().decode(encoding='UTF-8', errors='ignore').strip().lower())
                         for st in idautils.Strings() if len(str(st).strip()) > 0}
else:
    binary['strings'] = {st.ea: sub(r"\s+", '-', str(st).strip().lower())
                         for st in idautils.Strings() if len(str(st).strip()) > 0}

# processing imports:
import_modules = set()
import_functions = {}


def imp_cb(ea, name, ord):
    if name and ea:
        import_functions[ea] = str(name).strip().lower()
    return True


nimps = idaapi.get_import_module_qty()
for i in range(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print("Failed to get import module name for #%d" % i)
        continue

    import_modules.add(name.strip().lower())
    idaapi.enum_import_names(i, imp_cb)

binary['import_modules'] = list(import_modules)
binary['import_functions'] = import_functions
binary['disassembled_at'] = now_str


comments = list()


fn_ending_blk_sea = defaultdict(lambda: list())
for seg_ea in Segments():
    for function_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
        funcfc = idaapi.FlowChart(idaapi.get_func(function_ea))
        for bblock in funcfc:
            if len(list(bblock.succs())) < 1:
                fn_ending_blk_sea[function_ea].append(blocks[bblock.start_ea])


for seg_ea in Segments():
    for function_ea in Functions(get_segm_start(seg_ea), get_segm_end(seg_ea)):
        funcfc = idaapi.FlowChart(idaapi.get_func(function_ea))
        function = functions[function_ea]

        func_blks = list(funcfc)
        for bblock in func_blks:

            sblock = blocks[bblock.start_ea]
            sblock['ins'] = []

            for head in Heads(bblock.start_ea, bblock.end_ea):
                comments.extend(get_comments(
                    binary['_id'], function['_id'], sblock['_id'], head))
                mne = idc.print_insn_mnem(head)
                if mne == "":
                    continue
                mne = idc.GetDisasm(head).split()[0]
                mne = mne.lower()
                oprs = []
                oprs_tp = []
                for i in range(5):
                    if cleanStack == 1:
                        idc.OpOff(head, i, 16)
                    opd = idc.print_operand(head, i)
                    tp = idc.get_operand_type(head, i)
                    if opd == "":
                        continue
                    oprs.append(opd)
                    oprs_tp.append(tp)

                if idaapi.is_call_insn(head):
                    calls = [x.to for x in XrefsFrom(
                        head, idaapi.XREF_FAR) if x.to in fn_ending_blk_sea]
                    for x in calls:
                        if x in blocks:
                            sblock['calls'].append(blocks[x]['_id'])
                            for eea_ending_blk in fn_ending_blk_sea[x]:
                                eea_ending_blk['calls'].append(sblock['_id'])

                sblock['ins'].append({
                    'ea': head,
                    'mne': mne,
                    'oprs': oprs,
                    'oprs_tp': oprs_tp,
                })
            sblock['ins_c'] = len(sblock['ins'])

            # flow chart
            for succ_block in bblock.succs():
                succ_block = func_blks[succ_block.id]
                sblock['calls'].append(blocks[succ_block.start_ea]['_id'])

binary['functions_count'] = len(functions)

data = {
    'bin': binary,
    'functions': functions.values(),
    'blocks': blocks.values(),
    'comments': comments,
    'functions_src': []
}

# with open('%s.json' % (file_name), 'w') as outfile:
with codecs.open(file_name + '.asm.json', 'w', encoding='utf-8') as outfile:
    json.dump(data, outfile, ensure_ascii=False)

idc.qexit(0)
