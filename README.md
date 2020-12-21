# JARV1S-Disassembler

 ![Build and Release Ghidra JAR](https://github.com/L1NNA/JARV1S-Disassembler/workflows/Build%20and%20Release%20Ghidra%20JAR/badge.svg) ![Ghidra Extractor for Capa](https://github.com/L1NNA/JARV1S-Disassembler/workflows/Ghidra%20Extractor%20for%20Capa/badge.svg) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?&maxAge=86400)

Universal disassembly generation and processing for JARV1S/Kam1n0

The package will detect if IDA Pro is available in the path. If not, it will download and use Ghidra.

### :rocket: Installation:
Required: Python 3+. [Optional: OpenJDK 13+]
```bash
pip install git+https://github.com/L1NNA/JARV1S-Ghidra@master
```
### :fire: Usage:
Example:
```bash
python -m jvd binary_file_to_decompile
```
Batch mode: (process files end with `.o` in the `bins` folder)
```bash
python -m jvd bins --ext=.o
```
If IDA Pro is not in the path, Ghidra jar will be downloaded and installed. 
During the first run, the required jar and JDK will be downloaded to `~/.jarv1s-ghidra` if needed.
Options:
```bash
usage: python -m jvd <file> [options]

positional arguments:
  file                  The binary file.

optional arguments:
  -h, --help            show this help message and exit
  --dis {ida,ghidra}    The disassembler
  --ext EXT             If the input is a folder, the file extension to
                        include
  --cfg                 Generate CFG matrix
  --capa                Analyze by capa
  --verbose {-1,0,1,2}

```

### :star: Contributors:
- Steven Ding - Queen's Computing
- Litao Li - Queen's Computing 
- Christopher Bennett - Carleton University
- Miguel Garzon - University of Ottawa, Bell Canada

### 🌵 Used in `requirements.txt`:
```
git+https://github.com/L1NNA/JARV1S-Ghidra@master
```
