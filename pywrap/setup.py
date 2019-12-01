from distutils.core import setup
setup(
    name='ghidrapy',
    packages=['ghidrapy'],
    version='0.0.1',
    license='Apache 2.0',
    description='Ghidra disassembler through python.',
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
