# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


import capa.features.extractors.helpers
from capa.features import (
    ARCH_X32,
    ARCH_X64,
    MAX_BYTES_FEATURE_SIZE,
    THUNK_CHAIN_DEPTH_DELTA,
    Bytes,
    String,
    Characteristic,
)
from capa.features.insn import API, Number, Offset, Mnemonic
from jvd.capa.data import DataUnit
from jvd.normalizer.syntax import get_opr_constant, Assembly, get_opr_imm_str
import string
import re

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40
PATTERN_HEXNUM = re.compile(r"[+\-] (?P<num>0x[a-fA-F0-9]+)")
PATTERN_SINGLENUM = re.compile(r"[+\-] (?P<num>[0-9])")


def get_arch(f):
    bits = f.unit.obj.bin.bits
    if bits == 'b32':
        return ARCH_X32
    elif bits == 'b64':
        return ARCH_X64
    raise ValueError("unexpected architecture")


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
    for entry in unit.import_names.get(insn.ea, []):
        yield API(entry)


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
    if insn.is_mv_stack:
        return

    if insn.mne in unit.syntax.operations:
        if unit.syntax.operations[insn.mne].jmp:
            return

    for const in get_opr_constant(insn.oprs, insn.oprs_tp):
        yield Number(const), insn.ea
        yield Number(const, arch=get_arch(f)), insn.ea


def __read_byte(unit: DataUnit, addr, num_bytes=MAX_BYTES_FEATURE_SIZE):
    offset = addr - unit.bin.base_addr
    return unit.fbytes[offset:  offset + num_bytes]


def __find_data_ref(unit: DataUnit, ea, max_depth=10):
    """ search for data reference from instruction, return address of instruction if no reference exists """
    depth = 0

    while True:
        data_refs = unit.ins_dat_ref.get(ea, [])
        if len(data_refs) != 1:
            break
        if ea == data_refs[0]:
            break
        depth += 1
        if depth > max_depth:
            break
        ea = data_refs[0]

    return ea


def __detect_ascii_len(unit, addr):
    ascii_len = 0
    offset = addr - unit.bin.base_addr
    char = unit.buffer[offset]
    while char < 127 and chr(char) in string.printable:
        ascii_len += 1
        offset += 1
        char = unit.buffer[offset]
    if char == 0:
        return ascii_len
    return 0


def __detect_unicode_len(unit, addr):
    unicode_len = 0
    offset = addr - unit.bin.base_addr
    char = unit.buffer[offset]
    second_char = unit.buffer[offset + 1]
    while char < 127 and chr(char) in string.printable and second_char == 0:
        unicode_len += 2
        offset += 2
        char = unit.buffer[offset]
        second_char = unit.buffer[offset + 1]
    if char == 0 and second_char == 0:
        return unicode_len
    return 0


def extract_insn_bytes_features(f, bb, insn):
    """parse referenced byte sequences

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    ref = __find_data_ref(f.unit, insn.ea)
    if ref != insn.ea:
        extracted_bytes = __read_byte(
            f.unit, ref)
        if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
            yield Bytes(extracted_bytes), insn.ea


def __read_string(unit, addr):
    alen = __detect_ascii_len(unit, addr)
    if alen > 1:
        return __read_byte(unit, addr, alen).decode("utf-8")
    ulen = __detect_unicode_len(unit, addr)
    if ulen > 2:
        return __read_byte(unit, addr, ulen).decode("utf-16")


def extract_insn_string_features(f, bb, insn):
    """parse instruction string features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push offset aAcr     ; "ACR  > "
    """

    ref = __find_data_ref(f.unit, insn.ea)
    if ref != insn.ea:
        found = __read_string(f.unit, ref)
        if found:
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
    for operand in insn.oprs:
        if not "ptr" in operand:
            continue
        if "esp" in operand or "ebp" in operand or "rbp" in operand:
            continue
        number = 0
        number_hex = re.search(PATTERN_HEXNUM, operand)
        number_int = re.search(PATTERN_SINGLENUM, operand)
        if number_hex:
            number = int(number_hex.group("num"), 16)
            number = -1 * number if number_hex.group().startswith("-") else number
        elif number_int:
            number = int(number_int.group("num"))
            number = -1 * number if number_int.group().startswith("-") else number
        if number_hex or number_int:
            yield Offset(number), insn.ea
            yield Offset(number, arch=get_arch(f)), insn.ea


def contains_stack_cookie_keywords(ins):
    """check if string contains stack cookie keywords

    Examples:
        xor     ecx, ebp ; StackCookie
        mov     eax, ___security_cookie
    """
    for v in ins.oprs:
        v = v.strip().lower()
        if "cookie" not in v:
            return False
        if any(keyword in v for keyword in ("stack", "security")):
            return True
    return None


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """

    if insn.mne not in ("xor", "xorpd", "xorps", "pxor"):
        return

    operands = insn.oprs
    if operands[0] == operands[1]:
        return

    if contains_stack_cookie_keywords(insn):
        return

    yield Characteristic("nzxor"), insn.ea


def extract_insn_mnemonic_features(f, bb, insn):
    """parse instruction mnemonic features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    yield Mnemonic(insn.mne), insn.ea


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    TODO:
        IDA should be able to do this..
    """

    if insn.mne not in ["push", "mov"]:
        return

    operands = insn.oprs
    for operand in operands:
        if "fs:" in operand and "0x30" in operand:
            yield Characteristic("peb access"), insn.offset
        elif "gs:" in operand and "0x60" in operand:
            yield Characteristic("peb access"), insn.offset


def extract_insn_segment_access_features(f, bb, insn):
    """ parse the instruction for access to fs or gs """
    operands = insn.oprs
    for operand in operands:
        if "fs:" in operand:
            yield Characteristic("fs access"), insn.offset
        elif "gs:" in operand:
            yield Characteristic("gs access"), insn.offset


def extract_insn_cross_section_cflow(f, bb, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    u: DataUnit
    u = f.unit
    s: Assembly
    s = u.syntax
    if insn.mne in s.operations and s.operations[insn.mne].jmp is True:

        if len(insn.cr) > 0:
            for target in insn.cr:
                if u.find_seg(insn.ea) != u.find_seg(target):
                    yield Characteristic("cross section flow"), insn.ea
        elif len(insn.oprs) > 0 and insn.oprs[0].startswith("0x"):
            target = int(insn.oprs[0], 16)
            if u.find_seg(insn.ea) != u.find_seg(target):
                yield Characteristic("cross section flow"), insn.ea


def extract_function_calls_from(f, bb, insn):
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    u: DataUnit
    u = f.unit
    s: Assembly
    s = u.syntax
    if insn.mne in s.operations and s.operations[insn.mne].jmp is True:
        for ref in insn.cr:
            yield Characteristic("calls from"), ref


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
    if insn.mne in s.operations and s.operations[insn.mne].jmp is True:
        if len(insn.oprs) > 0:
            opr = insn.oprs[0]
            if opr.startswith("0x"):
                return
            if "qword ptr" in opr and "rip" in opr:
                return
            if opr.startswith("dword ptr [0x"):
                return
            yield Characteristic("indirect call"), insn.ea


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
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)
