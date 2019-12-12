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
    name='ghidrapy',
    packages=['ghidrapy'],
    version='0.0.4',
    license='Apache 2.0',
    description='Ghidra disassembler through python. Output formatted for Kam1n0 and JARV1S.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Steven Ding',
    author_email='ding@cs.queensu.ca',
    url='https://github.com/L1NNA/JARV1S-Ghidra',
    download_url='https://github.com/L1NNA/JARV1S-Ghidra/archive/v0.0.1.tar.gz',
    keywords=['Disassembler', 'Ghidra'],
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
