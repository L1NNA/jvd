from jvd.unpacker.p7zip import unzip_if_applicable
from jvd.utils import m_map, grep_ext, get_file_type
from tqdm import tqdm
from functools import partial
import os


def unpack_all(folder, ext, file_types=('elf', 'pe')):
    files = grep_ext(folder, ext)

    unzip_func = partial(
        unzip_if_applicable,
        keep_single_only=True,
        rename_ext=True,
        remove_original=True,
        rename_original=True)

    for _, _ in tqdm(m_map(
            unzip_func, files), total=len(files)):
        pass

    for f in grep_ext(folder, '.bin'):
        f_type = get_file_type(f)
        if not f_type.lower().startswith(file_types):
            os.remove(f)
