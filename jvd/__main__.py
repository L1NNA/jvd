import sys
import logging
import argparse
import os
from jvd import ida_available, get_disassembler
from jvd.installer import make

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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        usage='python -m jvd <file> [options]',
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='The binary file.'
    )
    disassember = 'ghidra' if not ida else 'ida'
    disassemblers = ['ghidra'] if not ida else ['ida', 'ghidra']
    parser.add_argument(
        '--dis',
        choices=disassemblers,
        default=disassember,
        help='The disassembler'
    )
    parser.add_argument(
        '--ext',
        default='.bin',
        help='If the input is a folder, the file extension to include'
    )
    parser.add_argument(
        '--cfg', dest='cfg',
        action='store_true', help='Generate CFG matrix')
    parser.add_argument(
        '--capa', dest='capa',
        action='store_true', help='Analyze by capa')
    parser.add_argument(
        '--decompile', dest='decompile',
        action='store_true',
        help='Decomiple the code (if IDA is chosen as disassembler, it will use Ghidra to decompile and merge.')
    parser.add_argument(
        '--verbose', dest='verbose',
        type=int, choices=range(-1, 3), default=-1)
    if is_src_dir:
        parser.add_argument(
            '--make', dest='make',
            action='store_true',
            help='Make the installer for offline usage.')
    flags = parser.parse_args()

    if is_src_dir and flags.make:
        make()
    else:
        if flags.dis is not None:
            disassember = flags.dis
        f = flags.file
        if not f:
            logging.error('You have to supply at least a file or a path.')
        else:
            disassember = get_disassembler(disassember)

            if os.path.isfile(f) and not os.path.isdir(f):
                _, logs = disassember.disassemble(
                    f, cfg=flags.cfg, capa=flags.capa, no_result=True,
                    verbose=flags.verbose, decompile=flags.decompile)
                if len(logs) > 0:
                    for l in logs:
                        print(logs)
            else:
                disassember.disassemble_all(
                    f, file_ext=flags.ext, cfg=flags.cfg, capa=flags.capa,
                    verbose=flags.verbose, decompile=flags.decompile)
