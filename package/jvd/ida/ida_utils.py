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
from ida_nalt import *
from idautils import *
from idaapi import *
from ida_name import *
from idc import *
import idaapi
import ida_func
import json
from collections import defaultdict
import sys


def now_str(): return datetime.now().isoformat()


tkn_skips = ('::', 'libname', 'j_')
# rebase = int(os.getenv('K_REBASE', 0))
cleanStack = int(os.getenv('K_CLEANSTACK', 0))


def _iter_extra_comments(ea, start):
    end = get_first_free_extra_cmtidx(ea, start)
    lines = [get_extra_cmt(ea, idx) for idx in
             range(start, end)]
    lines = [line if line else '' for line in lines]
    return "\n".join(lines)


def get_comments(binary_id, function_id, block_id, ea, created_at):
    comments = []
    text = idc.get_cmt(ea, 1)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'repeatable',
                         'content': text, 'address': ea, 'created_at': created_at})
    text = idc.get_cmt(ea, 0)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'regular',
                         'content': text, 'address': ea, 'created_at': created_at})
    text = _iter_extra_comments(ea, E_PREV)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'anterior',
                         'content': text, 'address': ea, 'created_at': created_at})
    text = _iter_extra_comments(ea, E_NEXT)
    if text and len(text) > 0:
        comments.append({'binary_id': binary_id, 'function_id': function_id,
                         'blk_id': block_id, 'author': 'ida', 'category': 'posterior',
                         'content': text, 'address': ea, 'created_at': created_at})
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
        if is_call_insn(instr):
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
            if api_flags & FUNC_LIB == True or api_flags & FUNC_THUNK:
                tmp_api_name = get_name(
                    tmp_api_address, GN_VISIBLE | calc_gtn_flags(0, tmp_api_address))
                if tmp_api_name:
                    apis.append(tmp_api_name)
            else:
                calls += 1
    return calls, apis


def get_exports():
    exports = {e[2]: e[3] for e in Entries()}
    return exports


def isLibrary(fn):
    fn = get_func(fn)
    if fn is None:
        return True
    name = get_func_name(fn.start_ea)
    for x in tkn_skips:
        if x in name:
            return True
    return fn.flags & FUNC_LIB == FUNC_LIB


def tooShort(fc):
    if fc.size > 1:
        return False
    if fc.size < 1:
        return True
    hds = [h for h in Heads(fc[0].startEA, fc[0].endEA)]
    return len(hds) < 3


def no_callers(fn_ea):
    exports = get_exports()
    fea = GetFunctionAttr(fn_ea, FUNCATTR_START)
    if fea in exports:
        return False
    if len(list(CodeRefsTo(fea, 1))) < 1:
        return True
    return False


def get_bin_hash():
    sha256 = retrieve_input_file_sha256()
    if sha256 is None:
        sha256 = GetInputFileMD5()
    sha256 = sha256.hex()
    return sha256


def get_processor():
    info = get_inf_structure()
    processor = info.procName.lower()
    if processor.startswith('mips'):
        processor = 'mips'
    return processor


def get_binary_with_functions():
    binary = {}
    # if rebase == 1:
    #     rebase_program(-1 * get_imagebase(), 0)

    binary_name = get_input_file_path()
    binary['name'] = binary_name
    binary['_id'] = get_bin_hash()
    binary['base'] = get_imagebase()

    info = get_inf_structure()
    bits = "b32"
    endian = "be"
    endian = "be" if info.is_be() else "le"
    if info.is_32bit():
        bits = "b32"
    if info.is_64bit():
        bits = "b64"

    binary['architecture'] = get_processor()
    binary['endian'] = endian
    binary['bits'] = bits
    binary['disassembler'] = 'ida'
    binary['compiler'] = get_compiler_name(info.cc.id)
    binary['description'] = ""
    binary['strings'] = {
        st.ea: str(st)
        for st in Strings() if len(str(st).strip()) > 0}

    import_modules = set()
    import_functions = {}

    nimps = get_import_module_qty()
    for i in range(0, nimps):
        name = get_import_module_name(i)
        if not name:
            print("Failed to get import module name for #%d" % i)
            continue

        def imp_cb(ea, f_name, ord):
            if f_name and ea:
                if f_name.startswith("__imp_"):
                    f_name = f_name[len("__imp_"):]
                f_name = str(f_name).strip()
                import_functions[ea] = (name, f_name, ord)
            return True

        import_modules.add(name.strip())
        enum_import_names(i, imp_cb)

    binary['import_modules'] = list(import_modules)
    binary['import_functions'] = import_functions
    binary['export_functions'] = get_exports()
    binary['disassembled_at'] = now_str()
    binary['seg'] = {}
    for seg_ea in Segments():
        binary['seg'][seg_ea] = idaapi.get_segm_name(seg_ea)


    functions = get_functions()
    binary['functions_count'] = len(functions)
    return binary, functions


def get_functions():
    sha256 = get_bin_hash()
    functions = {}
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
            functions['xref'] = []
            function['tags'] = ['ida-lib'] if isLibrary(function_ea) else []
            functions[function_ea] = function
            func_blocks = list(idaapi.FlowChart(idaapi.get_func(function_ea)))
            function['bbs_len'] = len(func_blocks)

    callees = defaultdict(set)
    for seg_ea in Segments():
        for function_ea in Functions(get_segm_start(seg_ea), get_segm_end(seg_ea)):
            for ref_ea in CodeRefsTo(function_ea, 0):
                ref_func = get_func(ref_ea)
                if ref_func and ref_func.start_ea in functions:
                    functions[function_ea]['calls'].append(
                        functions[ref_func.start_ea]['_id'])
                functions[function_ea]['xref'].append(ref_ea)
    return functions


def get_all(function_eas: list = None, with_blocks=True):

    if function_eas is None:
        function_eas = []
        for seg_ea in Segments():
            for function_ea in Functions(get_segm_start(seg_ea), get_segm_end(seg_ea)):
                function_eas.append(function_ea)

    binary, functions = get_binary_with_functions()
    set_function_eas = set(function_eas)
    comments = list()
    blocks = {}
    sha256 = get_bin_hash()
    processor = get_processor()
    time_str = now_str()

    if with_blocks:
        for function_ea in function_eas:
            func_blocks = FlowChart(get_func(function_ea))
            function = functions[function_ea]
            for bblock in func_blocks:

                m = hashlib.sha256()
                m.update(sha256.encode())
                m.update('b'.encode())
                m.update(str(bblock.start_ea).encode())

                sblock = dict()
                sblock['_id'] = m.hexdigest()
                sblock['addr_start'] = bblock.start_ea
                if processor == 'arm':
                    sblock['addr_start'] += get_sreg(bblock.start_ea, 'T')
                sblock['addr_end'] = bblock.end_ea
                sblock['name'] = 'loc_' + format(bblock.start_ea, 'x').upper()
                sblock['ins'] = []
                sblock['bin_id'] = sha256
                sblock['func_id'] = function['_id']
                sblock['calls'] = []
                blocks[bblock.start_ea] = sblock

        fn_ending_blk_sea = defaultdict(lambda: list())
        for function_ea in function_eas:
            funcfc = FlowChart(get_func(function_ea))
            for bblock in funcfc:
                if len(list(bblock.succs())) < 1:
                    fn_ending_blk_sea[function_ea].append(
                        blocks[bblock.start_ea])

        for function_ea in function_eas:
            funcfc = FlowChart(get_func(function_ea))
            function = functions[function_ea]

            func_blks = list(funcfc)
            for bblock in func_blks:

                sblock = blocks[bblock.start_ea]
                sblock['ins'] = []
                dat = {}
                sblock['dat'] = dat
                decoded = None

                for head in Heads(bblock.start_ea, bblock.end_ea):
                    comments.extend(get_comments(
                        binary['_id'], function['_id'], sblock['_id'], head, time_str))

                    refdata = list(DataRefsFrom(head))
                    if len(refdata) > 0:
                        for ref in refdata:
                            dat[head] = format(get_qword(ref), 'x')[::-1]

                    mne = print_insn_mnem(head)
                    if mne == "":
                        continue
                    mne = GetDisasm(head).split()[0]
                    mne = mne.lower()
                    oprs = []
                    oprs_tp = []
                    for i in range(5):
                        if cleanStack == 1:
                            OpOff(head, i, 16)
                        opd = print_operand(head, i)
                        tp = get_operand_type(head, i)
                        if len(opd) < 1:
                            continue
                        oprs.append(opd)

                        if tp == 5:
                            if not decoded:
                                decoded = idautils.DecodeInstruction(head)
                            dt = decoded.ops[i].dtype
                            tp = tp * (dt + 1)
                            # tp/5 to get the size
                        oprs_tp.append(tp)

                    if is_call_insn(head):
                        calls = [x.to for x in XrefsFrom(
                            head, XREF_FAR) if x.to in fn_ending_blk_sea]
                        for x in calls:
                            if x in blocks:
                                sblock['calls'].append(blocks[x]['_id'])
                                for eea_ending_blk in fn_ending_blk_sea[x]:
                                    eea_ending_blk['calls'].append(
                                        sblock['_id'])

                    sblock['ins'].append({
                        'ea': head,
                        'mne': mne,
                        'oprs': oprs,
                        'oprs_tp': oprs_tp,
                        'dr': list(idautils.DataRefsFrom(head)),
                        'cr': list(idautils.CodeRefsFrom(head, False)),
                    })
                sblock['ins_c'] = len(sblock['ins'])

                # flow chart
                for succ_block in bblock.succs():
                    succ_block = func_blks[succ_block.id]
                    sblock['calls'].append(blocks[succ_block.start_ea]['_id'])
                sblock['calls'] = list(set(sblock['calls']))
    return {
        'bin': binary,
        'functions': [f for f in functions.values() if f['addr_start'] in set_function_eas],
        'blocks': list(blocks.values()),
        'comments': comments,
        'functions_src': []
    }
