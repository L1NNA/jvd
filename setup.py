from setuptools import setup


from os import path
this_directory = path.abspath(path.dirname(__file__))
this_directory = path.abspath(path.join(this_directory, path.pardir))
readme = path.join(this_directory, 'README.md')
long_description = ""
if path.exists(readme):
    with open(readme, encoding='utf-8') as f:
        long_description = f.read()


setup(
    name='jvd',
    packages=['jvd'],
    package_data={'jvd': ['jvd/*.py', 'jvd/**/*.py',
                          'jvd/*.json', 'jvd/**/*.json']},
    version='0.0.9',
    include_package_data=True,
    license='Apache 2.0',
    description='Unified disassembler for JARV1S/Kam1n0',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Steven Ding',
    author_email='ding@cs.queensu.ca',
    url='https://github.com/L1NNA/JARV1S-Disassembler',
    download_url='https://github.com/L1NNA/JARV1S-Disassembler',
    keywords=['Disassembler', 'Ghidra', 'JARV1S', 'IDA'],
    install_requires=[
        'requests',
        'tqdm',
        'pytz',
        'flask-socketio',
        'python-dateutil',
        'python-magic-bin; sys_platform == "win32"',
        'python-magic-bin; sys_platform == "darwin"',
        'python-magic; sys_platform == "linux"',
        'flare-capa >= 1.6',
        'setuptools',
        'unipacker >= 1.0.5',
        'pygments',
        'javalang >= 0.13.0',
        'pydot >= 1.4.2',
        'networkx'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
