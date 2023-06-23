from collections import defaultdict
from jvd.normalizer.syntax import get_definition
import sys
from jvd.utils import AttrDict


class DataUnit:
    def __init__(self, json_obj, file_path):
        super().__init__()
        with open(file_path, "rb") as f:
            self.fbytes = f.read()

        self.obj = AttrDict.from_nested_dict(json_obj)
        if not 'data' in self.obj.bin:
            self.obj.bin.data = {}
        if not 'strings' in self.obj.bin:
            self.obj.bin.strings = {}
        self.map_b = defaultdict(list)
        for b in self.obj.blocks:
            b.address = b.addr_start
            self.map_b[b.addr_f].append(b)

        # flattened to nested
        self.map_f = {}
        self.map_f_xcall = defaultdict(list)
        for f in self.obj.functions:
            f.unit = self
            f.blocks = self.map_b.get(f.addr_start, [])
            self.map_f[f.addr_start] = f
            if not hasattr(f, 'calls'):
                f.calls = []
            for c in f.calls:
                self.map_f_xcall[c].append(f)

        self.map_b = {}
        for b in self.obj.blocks:
            self.map_b[b.addr_start] = b

        self.ins_dat_ref = {}
        for b in self.obj.blocks:
            if not hasattr(b, 'calls'):
                b.calls = []
            if not hasattr(b, 'ins'):
                b.ins = []
            for i in b.ins:
                if not hasattr(i, 'dr'):
                    i.dr = []
                if not hasattr(i, 'cr'):
                    i.cr = []
                if not hasattr(i, 'oprs'):
                    i.oprs = []
                if len(i.dr) > 0:
                    self.ins_dat_ref[i.ea] = i.dr
        # print('##', self.obj.bin.architecture)
        self.syntax = get_definition(self.obj.bin.architecture)
        self.import_names = None  # self.obj.bin.import_functions
        self.seg_addr = sorted(
            [int(k) for k in self.obj.bin.seg.keys()]) + [sys.maxsize]
        self.find_seg = lambda v: next(
            x[0] for x in enumerate(self.seg_addr) if x[1] > v)
