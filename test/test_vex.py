import os

from jvd.sym import dump_sim
from jvd.utils import read_gz_js


def test_vex():
    bin = os.path.join('test', 'test_jvd', 'crackme')
    obj = dump_sim(bin, function='authenticate')
    target = obj['functions'][0]
    assert target['name'] == 'authenticate'
    found = False
    for p in target['paths']:
        for r in p['vars_res']:
            if 'SOSNEAKY' in str(r):
                found = True
    assert found
