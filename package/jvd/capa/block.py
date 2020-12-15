
import sys
import string
import struct

import capa.features.extractors.ida.helpers as helpers
from capa.features import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.ida import helpers
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
import string
from jvd.normalizer.syntax import Assembly, get_opr_imm_str


def get_printable_len(op, op_type):

    chars, size = get_opr_imm_str(op, op_type)

    if not chars or not size:
        return 0

    def is_printable_ascii(chars):
        if sys.version_info[0] >= 3:
            return all(c < 127 and chr(c) in string.printable for c in chars)
        else:
            return all(ord(c) < 127 and c in string.printable for c in chars)

    def is_printable_utf16le(chars):
        if sys.version_info[0] >= 3:
            if all(c == 0x00 for c in chars[1::2]):
                return is_printable_ascii(chars[::2])
        else:
            if all(c == "\x00" for c in chars[1::2]):
                return is_printable_ascii(chars[::2])

    if is_printable_ascii(chars):
        return size

    if is_printable_utf16le(chars):
        return size // 2

    return 0


def is_mov_imm_to_stack(f, insn):
    """verify instruction moves immediate onto stack

    args:
        insn (IDA insn_t)
    """
    if hasattr(insn, 'is_mv_stack'):
        return insn.is_mv_stack
    insn.is_mv_stack = False
    if not insn.mne.startswith("mov"):
        return False

    if len(insn.oprs) < 2:
        return False

    if not all(c in string.hexdigits for c in insn.oprs[1]):
        return False

    if f and f.unit and f.unit.syntax:
        syntax: Assembly
        if insn.oprs[0] in syntax.registers:
            if syntax.registers[insn.oprs[0]] == 'GEN':
                return False
    insn.is_mv_stack = True
    return int(insn.oprs[1], 16), insn.oprs_tp[1]


def bb_contains_stackstring(f, bb):
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    count = 0
    for insn in bb.ins:
        s_var, s_var_type = is_mov_imm_to_stack(f, insn)
        if s_var:
            count += get_printable_len(s_var, s_var_type)
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def extract_bb_stackstring(f, bb):
    """extract stackstring indicators from basic block

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    if bb_contains_stackstring(f, bb):
        yield Characteristic("stack string"), bb.start_ea


def extract_bb_tight_loop(f, bb):
    if bb._id in bb.calls:
        yield Characteristic("tight loop"), bb.start_ea


def extract_features(f, bb):
    """extract basic block features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for (feature, ea) in bb_handler(f, bb):
            yield feature, ea
    yield BasicBlock(), bb.start_ea


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)
