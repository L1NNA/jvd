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
    package_data={'jvd': ['jvd/*.py', 'jvd/**/*.py', 'jvd/*.json', 'jvd/**/*.json']},
    version='0.0.8',
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
