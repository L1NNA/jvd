import pathtools
import argparse
import os
from shutil import rmtree, unpack_archive
import magic


supported = (
    '7z', 'ace', 'adf', 'alzip', 'ape', 'ar', 'arc', 'arj',
    'bzip2', 'cab', 'chm', 'compress', 'cpio', 'deb', 'dms',
    'flac', 'gzip', 'iso', 'lrzip', 'lzh', 'lzip', 'lzma', 'lzop',
    'rar', 'rpm', 'rzip', 'shar', 'shn', 'tar', 'vhd', 'xz',
    'zip', 'zoo', 'zpaq',
    'gztar'

)

shutil_types = {
    'zip': 'zip', 'tar': 'tar', 'gzip tar': 'gztar'}

patool_tpyes = {
    'rar': 'rar'
}


def get_archive_type(file, file_type=None):

    if not file_type:
        file_type = magic.from_file(file)
    for x in shutil_types:
        if file_type.lower().startswith(x):
            return shutil_types[x]
    for x in patool_tpyes:
        if file_type.lower().startswith(x):
            return patool_tpyes[x]
    return None



def unpack(file, format=None, skip_existed=True, file_type=None):
    loc = file + '-unpacked'
    if os.path.exists(loc):
        if skip_existed:
            return os.path.abspath(loc), 'found existed archive'
        else:
            rmtree(loc)
    if not os.path.exists(loc):
        os.makedirs(loc)
    try:
        if not format:
            format = get_archive_type(file, file_type)
        if format in shutil_types.values():
            unpack_archive(
                filename=file, extract_dir=loc, format=format)
            return loc, 'extracted'

        patoolib._extract_archive(
            file, verbosity=-1, interactive=False, outdir=loc,
            format=format
        )
    except Exception as e:
        rmtree(loc)
        return None, 'failed extraction: {}'.format(str(e))
    return loc, 'extracted'


if __name__ == '__main__':
    # Archive('I:/MalBinZoo/test/test.r').extractall('I:/MalBinZoo/test/res')
    parser = argparse.ArgumentParser(
        usage='python -m jvd.unpack <file> [options]',
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='The archive file.'
    )
    parser.add_argument(
        '--format',
        choices=supported,
        default='auto',
        help='The disassembler'
    )
    flags = parser.parse_args()
    loc, log = unpack(flags.file, format=None if flags.format ==
                      'auto' else flags.format)
    print('loc', loc)
    print(log)
