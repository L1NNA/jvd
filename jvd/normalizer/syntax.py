import json
from typing import Dict, List
import os
import struct
from collections import defaultdict


class Register:
    def __init__(self):
        super().__init__()
        self.identifer = ''
        self.type = None
        self.size = 16


class Operation:
    def __init__(self):
        super().__init__()
        self.identifier = ''
        self.suffix = []
        self.jmp = False
        self.type = None


class Assembly:
    def __init__(self):
        super().__init__()
        self.operations: Dict[str, Operation]
        self.registers: Dict[str, Register]
        self.processor: str
        self.operations = {}
        self.registers = {}
        self.registers_cat = defaultdict(dict)
        self.processor = ''


def loadDefinition(data):
    if isinstance(data, str):
        data = os.path.join(os.path.dirname(
            os.path.abspath(__file__)
        ), data)
        with open(data) as rf:
            data = json.load(rf)
    data = data['Kam1n0-Architecture']

    suffix = {}
    if 'suffixGroups' in data:
        for s in data['suffixGroups']['suffixGroup']:
            suffix[s['_identifier']] = s['suffix']

    opr_group = {}
    if 'oprGroups' in data:
        for g in data['oprGroups']['oprGroup']:
            for o in g['opr']:
                opr_group[o] = g['_identifier']

    a = Assembly()
    a.processor = data['processor']
    for opr in data['operations']['operation'] + data['operationJmps']['operation']:
        o = Operation()
        o.identifier = opr['_identifier'].lower()
        if 'suffixGroup' in opr:
            o.suffix = [s.lower() for sg in opr['suffixGroup']
                        if sg in suffix for s in suffix[sg] if s]
            o.suffix = list(set(o.suffix))
        if o.identifier in opr_group:
            o.type = opr_group[o.identifier].lower()
        else:
            o.type = None
        a.operations[o.identifier] = o

    for opr in data['operationJmps']['operation']:
        identifier = opr['_identifier'].lower()
        if identifier in a.operations:
            a.operations[identifier].jmp = True

    for reg in data['registers']['register']:
        r = Register()
        r.identifer = reg['_identifier'].lower()
        r.type = reg['_category'].lower()
        r.size = int(reg['_length'])
        a.registers[r.identifer] = r
        a.registers_cat[r.type][r.identifer]=r
    return a


metapc: Assembly
arm: Assembly
mc68: Assembly
ppc: Assembly
tms320c6: Assembly

metapc = loadDefinition('metapc.json')
mc68 = loadDefinition('mc68.json')
arm = loadDefinition('arm.json')
ppc = loadDefinition('ppc.json')
tms320c6 = loadDefinition('tms320c6.json')

_arc2synctax = {
    'metapc': metapc,
    'mc68': mc68,
    '68330': mc68,
    'arm': arm,
    'ppc': ppc,
    'X86_64(x86_64)': metapc
}


def get_definition(arc) -> Assembly:
    if not arc:
        return None
    for k, v in _arc2synctax.items():
        if arc.startswith(k):
            return v
    return None


def is_constant(o, t):
    if t == 5 or (t & 0x00000008) or (t & 0x00004000):
        if isinstance(o, int) or all(c in '01234567890abcdefx' for c in o):
            return True
    return False


def is_mem_ref(o, t):
    if t == 2 or t == 4 or (t & 0x00000004):
        return True
    return False


def is_reg(o, t):
    if t == 1 or (t & 0x00000200):
        return True
    return False



def get_opr_constant(op, op_types):
    # ref: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/
    # Framework/SoftwareModeling/src/main/java/ghidra/program/model/
    # lang/OperandType.java#L90
    tps = [(o, int(t)) for o, t in zip(op, op_types)]
    ops = [o.lower() for o, t in tps if is_constant(o, t)]
    return ops


def get_opr_imm_str(opr, opr_type):
    t = int(opr_type)
    if not is_constant(opr, opr_type):
        return None, None

    op_value = opr if isinstance(opr, int) else int(opr, 16)

    size = None
    if t & 0x00010000 or t/5 == 0:
        size = 1
        chars = struct.pack("<B", op_value & 0xFF)
    elif t & 0x00020000 or t/5 == 5:
        size = 2
        chars = struct.pack("<H", op_value & 0xFFFF)
    elif t/5 == 2:
        size = 4
        chars = struct.pack("<I", op_value & 0xFFFFFFFF)
    elif t & 0x00040000 or t/5 == 7:
        size = 8
        chars = struct.pack("<Q", op_value & 0xFFFFFFFFFFFFFFFF)
    else:
        size = 4
        chars = struct.pack("<I", op_value & 0xFFFFFFFF)
        try:
            chars.decode()
        except Exception:
            chars = None
            size = None

    return chars, size


def norm_opr(mne, arc=None):
    mne = mne.lower()
    arc = get_definition(arc)
    if arc and mne in arc.operations:
        return arc.operations[mne]
    if not arc:
        for arc in [metapc, arm, mc68, ppc, tms320c6]:
            if mne in arc.operations:
                return arc.operations[mne]
    return None
