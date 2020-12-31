import subprocess
from jvd.resources import cache_all
from jvd.utils import download_file
import pip
import os
import platform
from shutil import copyfile, copy, rmtree, make_archive
import glob


path_current = os.path.dirname(os.path.abspath(__file__))


def make(dest='jvd_installer', package='jvd'):

    if not os.path.exists(dest):
        os.makedirs(dest)

    print()
    print('-' * 30)
    print('copying installation script...')
    print('-' * 30)
    install_script = os.path.join(path_current, 'install.py')
    print('script file:', install_script)
    with open(install_script, 'r') as rf:
        content = rf.read()
        content = content.replace('{package}', package)
        with open(os.path.join(dest, '__main__.py'), 'w') as wf:
            wf.write(content)

    dest_wheel = os.path.join(dest, 'wheels')
    if not os.path.exists(dest_wheel):
        os.makedirs(dest_wheel)

    print()
    print('-' * 30)
    print('building wheel for {} ...'.format(package))
    print('-' * 30)
    subprocess.run([
        'python', 'setup.py', 'bdist_wheel'
    ])
    for filename in glob.glob(os.path.join('dist', '*.*')):
        copy(filename, dest_wheel)
    if os.path.exists('build'):
        rmtree('build')
    if os.path.exists('dist'):
        rmtree('dist')
    if os.path.exists('jvd.egg-info'):
        rmtree('jvd.egg-info')

    cmd = [
        'pip3', 'download', '--dest', dest_wheel, '-r', 'requirements.txt'
    ]
    subprocess.run(cmd)
    # for p in ['win_amd64', 'linux_x86_64', 'macosx']:

    #     cmd = ['pip3',
    #            'download',
    #            '--dest',
    #            dest_wheel,
    #            '-r',
    #            'requirements.txt',
    #            '--platform',
    #            p,
    #            '--only-binary=:all:']

    #     result = subprocess.run(cmd)

    print()
    print('-' * 30)
    print('downloading libs....')
    print('-' * 30)
    cache_all(os.path.join(dest, 'libs'))

    print()
    print('-' * 30)
    print('making archive...')
    print('-' * 30)
    make_archive(dest + "_" + platform.system().lower(), 'zip', dest)
    rmtree(dest)
