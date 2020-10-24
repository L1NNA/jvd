import gzip
import json
from concurrent.futures import ProcessPoolExecutor
from tqdm import tqdm
from subprocess import check_call
import pathlib
import os


def _default_fs_mapper(file):
    if isinstance(file, dict):
        return file
    if file.with_suffix('.gz'):
        with gzip.open(
                file, 'rt',
                encoding='utf-8') as zipfile:
            return json.load(zipfile)
    else:
        with open(file, 'r', encoding='utf-8') as rf:
            return json.load(rf)


def get_arch(file):
    obj = _default_fs_mapper(file)
    return obj['bin']['_id'], obj['bin']['architecture'], obj['bin']['f_type'].split(',')[0]


def extract_types(bins_path):

    samples = []
    files = list(
        pathlib.Path(bins_path).glob('*.asm.json.gz'))
    with ProcessPoolExecutor(max_workers=50) as pool:
        with tqdm(total=len(files)) as progress:
            futures = []
            for f in files:
                future = pool.submit(
                    get_arch,
                    f)
                future.add_done_callback(
                    lambda p: progress.update())
                futures.append(future)

            for future in futures:
                result = future.result()
                if result:
                    samples.append(result)
    return samples


def _compress_bin(file):
    check_call(['gzip', os.path.abspath(str(file))])


def compress_bins(bins_path):
    files = list(
        pathlib.Path(bins_path).glob('*.bin'))
    with ProcessPoolExecutor(max_workers=50) as pool:
        with tqdm(total=len(files)) as progress:
            futures = []
            for f in files:
                future = pool.submit(
                    _compress_bin,
                    f)
                future.add_done_callback(
                    lambda p: progress.update())
                futures.append(future)

            for future in futures:
                result = future.result()
                pass


if __name__ == '__main__':
    bin_path = 'I:/MalBinZoo/bins'
    samples = extract_types(bin_path)
    with open(os.path.join(bin_path, os.pardir, 'types.csv'), 'a+') as f:
        for v in samples:
            f.write(','.join(v)+'\n')
    compress_bins(bin_path)
