# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


from jvd.normalizer.libc import is_libc
import capa.features.extractors.helpers as helpers
from capa.features.common import (
    ARCH_I386,
    ARCH_AMD64,
    MAX_BYTES_FEATURE_SIZE,
    THUNK_CHAIN_DEPTH_DELTA,
    Bytes,
    String,
    Characteristic,
)
from capa.features.insn import API, Number, Offset, Mnemonic
from jvd.capa.data import DataUnit
from jvd.capa.block import is_mov_imm_to_stack
from jvd.normalizer.syntax import get_opr_constant, Assembly, get_opr_imm_str, is_reg, is_mem_ref
import string
import re
import struct
import base64

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40
PATTERN_HEXNUM = re.compile(r"[+\-]\s*(?P<num>0x[a-fA-F0-9]+)")
PATTERN_HEXNUM_2 = re.compile(r"[+\-]\s*(?P<num>[a-fA-F0-9]+)[hH]")
PATTERN_SINGLENUM = re.compile(r"[+\-]\s*(?P<num>[0-9])")


def extract_insn_api_features(f, bb, insn):
    """parse instruction API features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        call dword [0x00473038]
    """

    unit: DataUnit = f.unit

    if len(insn.oprs) > 0 and is_libc(insn.oprs[0]):
        yield API(insn.oprs[0]), insn.ea

    if len(insn.cr) < 1:
        return

    for c in insn.cr + insn.dr:
        if str(c) in unit.obj.bin.import_functions:
            module, func, _ = unit.obj.bin.import_functions[str(c)]
            if '.dll' in module:
                module = module.replace('.dll', '')
            for symbol in helpers.generate_symbols(module, func):
                yield API(symbol), insn.ea

        # THUNK!!
        depth = 0
        _next = c
        while depth < THUNK_CHAIN_DEPTH_DELTA:
            if _next not in unit.map_f:
                break
            c_f = unit.map_f[_next]
            if len(c_f.blocks) != 1:
                break
            if len(c_f.blocks[0].ins) != 1:
                break
            if len(c_f.blocks[0].ins[0].cr) == 1:
                # code reference of thunked function to the symbol
                _next = c_f.blocks[0].ins[0].cr[0]
            elif len(c_f.blocks[0].ins[0].dr) == 1:
                # data reference of thunked function to the symbol
                _next = c_f.blocks[0].ins[0].dr[0]
            else:
                break
            if str(_next) in unit.obj.bin.import_functions:
                module, func, _ = unit.obj.bin.import_functions[str(_next)]
                if '.dll' in module:
                    module = module.replace('.dll', '')
                for symbol in helpers.generate_symbols(module, func):
                    yield API(symbol), insn.ea
            depth += 1


def extract_insn_number_features(f, bb, insn):
    """parse instruction number features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push    3136B0h         ; dwControlCode
    """
    unit: DataUnit
    unit = f.unit

    # get from cache (AttrDict will not add new attribute to json)
    syntax: Assembly
    syntax = f.unit.syntax
    if len(insn.oprs) < 1:
        return

    stk = insn.oprs[0].lower()
    if 'ADD' in insn.mne and any(reg in stk for reg in syntax.registers_cat['ptr'].keys()):
        return

    if len(insn.cr) < 1:
        return

    for const in get_opr_constant(insn.oprs, insn.oprs_tp, True):
        yield Number(const), insn.ea
        # yield Number(const, arch=get_arch(f)), insn.ea


def extract_insn_bytes_features(f, bb, insn):
    """parse referenced byte sequences

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    for ref in insn.dr:
        ref = str(ref)
        found = None
        # check string first (ghidra/ida put it there)
        if ref in f.unit.obj.bin.strings:
            found = f.unit.obj.bin.strings[ref]
            yield Bytes(found.encode("utf-16le")), insn.ea
        if found:
            return
        # then check referenced data
        if ref in f.unit.obj.bin.data:
            found = f.unit.obj.bin.data[ref]
            # found = struct.pack('<Q', int(found, base=16))
            # found = bytes.fromhex(found)
            found = base64.b64decode(found)
            yield Bytes(found), insn.ea
        # if ref != insn.ea:
        #     extracted_bytes = __read_byte(
        #         f.unit, ref)
        #     if extracted_bytes and not helpers.all_zeros(extracted_bytes):
        #         yield Bytes(extracted_bytes), insn.ea


def extract_insn_string_features(f, bb, insn):
    """parse instruction string features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push offset aAcr     ; "ACR  > "
    """

    for ref in insn.dr:
        ref = str(ref)
        if ref in f.unit.obj.bin.strings:
            found = f.unit.obj.bin.strings[ref]
            yield String(found), insn.ea


def extract_insn_offset_features(f, bb, insn):
    """parse instruction structure offset features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        .text:0040112F cmp [esi+4], ebx
    """
    syntax = f.unit.syntax
    for operand in insn.oprs:
        operand = operand.lower()
        if any(reg in operand for reg in syntax.registers_cat['ptr'].keys()):
            continue
        number = 0
        number_hex = re.search(PATTERN_HEXNUM, operand)
        number_hex_2 = re.search(PATTERN_HEXNUM_2, operand)
        number_int = re.search(PATTERN_SINGLENUM, operand)
        if number_hex:
            number = int(number_hex.group("num"), 16)
            number = -1 * number if number_hex.group().startswith("-") else number
        elif number_hex_2:
            number = int(number_hex_2.group("num"), 16)
            number = -1 * number if number_hex_2.group().startswith("-") else number
        elif number_int:
            number = int(number_int.group("num"))
            number = -1 * number if number_int.group().startswith("-") else number
        yield Offset(number), insn.ea
        # yield Offset(number, arch=get_arch(f)), insn.ea


def contains_stack_cookie_keywords(ins, blk, func):
    """check if string contains stack cookie keywords

    Examples:
        xor     ecx, ebp ; StackCookie
        mov     eax, ___security_cookie
    """
    full_str = ','.join(ins.oprs).lower()
    if 'cookie' in full_str:
        if any(keyword in full_str for keyword in ("stack", "security")):
            return True

    unit: DataUnit
    unit = func.unit
    if blk.addr_start == func.addr_start:
        if ins.ea < blk.addr_start + SECURITY_COOKIE_BYTES_DELTA:
            return True

    called = {
        c for c in blk.calls if c in unit.map_b and unit.map_b[c].addr_f == func.addr_start}

    if len(called) == 0 and ins.ea > blk.addr_end - SECURITY_COOKIE_BYTES_DELTA:
        return True

    return False


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """

    if insn.mne not in ("XOR", "XORPD", "XORPS", "PXOR"):
        return

    operands = insn.oprs
    if operands[0] == operands[1]:
        return

    if contains_stack_cookie_keywords(insn, bb, f):
        return

    yield Characteristic("nzxor"), insn.ea


def extract_insn_mnemonic_features(f, bb, insn):
    """parse instruction mnemonic features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    yield Mnemonic(insn.mne.lower()), insn.ea


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    TODO:
        IDA should be able to do this..
    """

    if insn.mne not in ["PUSH", "MOV"]:
        return

    operands = insn.oprs
    for operand in operands:
        operand = operand.lower()
        if "fs:" in operand and ("0x30" in operand or "30h" in operand):
            yield Characteristic("peb access"), insn.ea
        elif "gs:" in operand and ("0x60" in operand or "60h" in operand):
            yield Characteristic("peb access"), insn.ea


def extract_insn_segment_access_features(f, bb, insn):
    """ parse the instruction for access to fs or gs """
    if f.address == 0x180001068:
        print(insn)
    operands = insn.oprs
    for operand in operands:
        operand = operand.lower()
        if "fs:" in operand:
            yield Characteristic("fs access"), insn.ea
        elif "gs:" in operand:
            yield Characteristic("gs access"), insn.ea


def extract_insn_cross_section_cflow(f, bb, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    u: DataUnit
    u = f.unit
    if len(insn.cr) > 0:
        for target in insn.cr:
            if str(target) in u.obj.bin.import_functions:
                continue
            if u.find_seg(insn.ea) != u.find_seg(target):
                yield Characteristic("cross section flow"), insn.ea
    elif len(insn.oprs) > 0 and insn.oprs[0].startswith("0x"):
        target = int(insn.oprs[0], 16)
        if u.find_seg(insn.ea) != u.find_seg(target):
            yield Characteristic("cross section flow"), insn.ea


# def extract_function_calls_from(f, bb, insn):
#     """extract functions calls from features

#     most relevant at the function scope, however, its most efficient to extract at the instruction scope

#     args:
#         f (IDA func_t)
#         bb (IDA BasicBlock)
#         insn (IDA insn_t)
#     """
#     u: DataUnit
#     u = f.unit
#     s: Assembly
#     s = u.syntax
#     mne = insn.mne.lower()
#     if mne in s.operations and s.operations[mne].jmp is True:
#         for ref in insn.cr:
#             if ref in u.map_f_ea:
#                 yield Characteristic("calls from"), ref


def extract_function_indirect_call_characteristic_features(f, bb, insn):
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    u: DataUnit
    u = f.unit
    s: Assembly
    s = u.syntax
    mne = insn.mne
    if 'CALL' in mne:
        if len(insn.oprs) > 0:
            opr = insn.oprs[0].lower()
            if opr.startswith("0x"):
                return
            if "qword ptr" in opr and "rip" in opr:
                return
            if opr.startswith("dword ptr [0x"):
                return
            if "ptr_" in opr:
                return
            if is_mem_ref(opr, insn.oprs_tp[0]):
                yield Characteristic("indirect call"), insn.ea
            if is_reg(opr, insn.oprs_tp[0]):
                yield Characteristic("indirect call"), insn.ea


def extract_insn_obfs_call_plus_5_characteristic_features(f, bb, insn):
    """
    parse call $+5 instruction from the given instruction.
    """
    mne = insn.mne.lower()
    if mne != "call":
        return

    if len(insn.cr) > 0:
        for cr in insn.cr:
            if cr - insn.ea == 5:
                yield Characteristic("call $+5"), insn.ea


def extract_features(f, bb, insn):
    """extract instruction features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, ea) in inst_handler(f, bb, insn):
            yield feature, ea


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    # extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
    extract_insn_obfs_call_plus_5_characteristic_features,
)
