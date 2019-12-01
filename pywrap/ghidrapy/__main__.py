import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.StreamHandler()
    ])
if __name__ == "__main__":

    from ghidrapy.decompiler import process, cleanup
    process(sys.argv[1])
    cleanup(sys.argv[1])
