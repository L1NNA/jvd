
import sys
import string
import struct

from capa.features.common import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
import string
from jvd.normalizer.syntax import is_op_stack_var, get_opr_imm_str, is_constant


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
    insn.is_mv_stack = False, None
    if not insn.mne.startswith("MOV"):
        return insn.is_mv_stack
    

    if len(insn.oprs) < 2:
        return insn.is_mv_stack

    val = is_constant(insn.oprs[1], insn.oprs_tp[1], True)
    if not val:
        return insn.is_mv_stack

    if f and f.unit:
        stk = insn.oprs[0].lower()
        if is_op_stack_var(f.unit.obj.bin.architecture, stk):
            insn.is_mv_stack = val, insn.oprs_tp[1]
            return insn.is_mv_stack
    return insn.is_mv_stack


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
        yield Characteristic("stack string"), bb.addr_start


def extract_bb_tight_loop(f, bb):
    if bb.addr_start in bb.calls:
        yield Characteristic("tight loop"), bb.addr_start


def extract_features(f, bb):
    """extract basic block features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for (feature, ea) in bb_handler(f, bb):
            yield feature, ea
    yield BasicBlock(), bb.addr_start


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)
