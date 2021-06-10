import sys
import logging
import argparse
import os
from jvd import ida_available, get_disassembler, process_folder
from jvd.installer import make
from tqdm import tqdm
from jvd.utils import grep_ext
from shutil import rmtree


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.StreamHandler()
    ])

ida = ida_available
if not ida:
    logging.info('IDA is not available. Will use Ghidra instead.')


is_src_dir = os.path.exists('setup.py')


class CombinedFormatClass(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter):
    pass

banner = """
    ▄█        ▄█  ███▄▄▄▄   ███▄▄▄▄      ▄████████ 
    ███       ███  ███▀▀▀██▄ ███▀▀▀██▄   ███    ███ 
    ███       ███▌ ███   ███ ███   ███   ███    ███ 
    ███       ███▌ ███   ███ ███   ███   ███    ███ 
    ███       ███▌ ███   ███ ███   ███ ▀███████████ 
    ███       ███  ███   ███ ███   ███   ███    ███ 
    ███▌    ▄ ███  ███   ███ ███   ███   ███    ███ 
    █████▄▄██ █▀    ▀█   █▀   ▀█   █▀    ███    █▀  
    ▀                                               
        [by www.l1nna.com @ Queen's University]
"""


def entry_point():

    parser = argparse.ArgumentParser(
        usage='jvd <file> [options]',
        formatter_class=CombinedFormatClass,
        description=banner,
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='The binary file or the targeted path.'
    )

    group_gen = parser.add_argument_group('Gobal commands and toggles')
    parser.add_argument(
        '--ext',
        default=None,
        metavar='',
        help='If the input is a folder, the file extension to include. Default is all the files. '
        'Empty string will select files without any `.`.'
    )
    group_gen.add_argument(
        '--unpack', dest='unpack',
        action='store_true', help='Unpack before disassembling.')
    group_gen.add_argument(
        '--cleanup', dest='cleanup',
        action='store_true', help='Clean up the temporary folders.')
    group_gen.add_argument(
        '--verbose', dest='verbose',
        type=int, choices=range(-1, 3), default=-1)
    if is_src_dir:
        group_gen.add_argument(
            '--make', dest='make',
            action='store_true',
            help='Make the installer for offline usage.')

    group_dis = parser.add_argument_group('Disassembling and decompilation')
    disassember = 'ghidra' if not ida else 'ida'
    disassemblers = ['ghidra'] if not ida else ['ida', 'ghidra']
    group_dis.add_argument(
        '--dis', dest='disassemble',
        action='store_true', help='Disassemble all the applicable files.')
    group_dis.add_argument(
        '--dis-backend', dest='dis',
        choices=disassemblers,
        default=disassember,
        help='The disassembler'
    )
    group_dis.add_argument(
        '--dis-decompile', dest='decompile',
        action='store_true',
        help='Decomiple the code (if IDA is chosen as disassembler, it will use Ghidra to decompile and merge.')
    group_dis.add_argument(
        '--dis-capa', dest='capa',
        action='store_true', help='Analyze by capa')

    group_vex = parser.add_argument_group(
        'Vex IR code extraction and symbolic execution')
    group_vex.add_argument(
        '--vex', dest='vex',
        action='store_true', help='Extract vex code and execution path.')
    group_vex.add_argument(
        '--vex-tracelet', dest='tracelet',
        type=int, default=-1,
        metavar='',
        help='For vex processing, extract tracelet (>0) rather than full execution paths (-1).')
    group_vex.add_argument(
        '--vex-loop', dest='loop',
        type=int, default=2,
        metavar='',
        help='Maximum bound of loops in symbolic execution')
    group_vex.add_argument(
        '--vex-overlap', dest='overlap',
        action='store_true', help='The tracelets overlap each other.')

    group_src = parser.add_argument_group(
        'Source code processing')
    group_src.add_argument(
        '--src', dest='src',
        action='store_true', help='Extract AST/CPGs from a source file or a folder.')
    group_src.add_argument(
        '--src-lang', dest='lang',
        choices=['cpp', 'c', 'python', 'java'],
        default='c',
        help='The source code language.')

    flags = parser.parse_args()

    if is_src_dir and flags.make:
        make()
    elif flags.cleanup:
        folders = grep_ext(flags.file, '.tmp', type='d')
        for f in tqdm(folders):
            try:
                rmtree(f)
            except Exception as e:
                print(str(e), ':::', f)
    else:
        if flags.dis is not None:
            disassembler = flags.dis
        f = flags.file
        if flags.src:

            import jvd.src as src
            src.process_folder(
                f, flags.lang
            )
            return

        print('scanning files...')
        if f is not None and os.path.isfile(f):
            files = [f]
        else:
            files = grep_ext(f, ext=flags.ext)
        if not f:
            logging.error('You have to supply at least a file or a path.')
        else:
            if flags.disassemble or flags.unpack or flags.capa:
                print('processing...')
                process_folder(
                    files, capa=flags.capa, decompile=flags.decompile,
                    clean_up=False, ext=flags.ext, disassembler=disassembler,
                    verbose=flags.verbose, disassemble=flags.disassemble,
                    unpack=flags.unpack,
                )

            if flags.vex:
                print('processing vex...')
                import jvd.sym as sym
                sym.process_all(
                    files, verbose=flags.verbose,
                    tracelet=flags.tracelet, overlap=flags.overlap, loop=flags.loop)

        print('done')


if __name__ == "__main__":
    entry_point()
