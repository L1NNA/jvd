import sys
import logging
import argparse
import os
from jvd import ida_available

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.StreamHandler()
    ])

ida = ida_available
if not ida:
    logging.info('IDA is not available. Will use Ghidra instead.')


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
    parser.add_argument('--cfg', dest='cfg',
                        action='store_true', help='Generate CFG matrix')
    flags = parser.parse_args()
    if flags.dis is not None:
        disassember = flags.dis
    f = flags.file
    if not f:
        logging.error('You have to supply at least a file or a path.')
    else:
        if disassember == 'ida':
            from jvd.ida.ida import IDA
            disassember = IDA()
        else:
            from jvd.ghidra.decompiler import Ghidra
            disassember = Ghidra()

        if os.path.isfile(f) and not os.path.isdir(f):
            disassember.disassemble(f, cleanup=True, cfg=flags.cfg)
        else:
            disassember.disassemble_all(f, file_ext=flags.ext, cfg=flags.cfg, as_gzip=True)
