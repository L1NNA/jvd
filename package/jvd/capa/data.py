from collections import defaultdict
from jvd.normalizer.syntax import get_definition


class AttrDict(dict):
    """ Dictionary subclass whose entries can be accessed by attributes
        (as well as normally). (Added attributes will be ignored)
    """

    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

    @staticmethod
    def from_nested_dict(data):
        """ Construct nested AttrDicts from nested dictionaries. """
        if isinstance(data, dict):
            return AttrDict({key: AttrDict.from_nested_dict(data[key])
                             for key in data})
        if isinstance(data, list):
            return [AttrDict.from_nested_dict(d) for d in data]
        return data

    def __int__(self):
        if hasattr(self, 'addr_start'):
            return getattr(self, 'addr_start')
        return None


class DataUnit:
    def __init__(self, json_obj, file_path):
        super().__init__()
        with open(file_path, "rb") as f:
            self.fbytes = f.read()

        self.obj = AttrDict.from_nested_dict(json_obj)
        self.map_b = defaultdict(list)
        for b in self.obj.blocks:
            self.map_b[b.func_id].append(b)

        # flattened to nested
        for f in self.obj.functions:
            f.unit = self
            f.blocks = self.map_b.get(f._id, [])

        self.ins_dat_ref = {}
        for b in self.obj.blocks:
            for i in b.ins:
                if len(i.dr) > 0:
                    self.ins_dat_ref[i.ea] = i.dr
        self.syntax = get_definition(self.obj.bin.architecture)
        self.import_names = self.obj.bin.import_functions
        self.seg_addr = sorted(self.obj.bin.seg.keys())
        self.find_seg = lambda v: next(
            x[0] for x in enumerate(self.seg_addr) if x[1] > v)
