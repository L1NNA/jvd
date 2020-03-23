# JARV1S-Disassembler

[![](https://github.com/L1NNA/JARV1S-Ghidra/workflows/Build%20and%20Release%20JAR/badge.svg)](https://github.com/L1NNA/JARV1S-Ghidra/actions) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?&maxAge=86400)

Universal disassembly generation and processing for JARV1S/Kam1n0

The package will detect if IDA Pro is available in the path. If not, it will use Ghidra.

### :rocket: Installation:
Required: Python 3+. [Optional: OpenJDK 13+]
```bash
pip install git+https://github.com/L1NNA/JARV1S-Ghidra@master#subdirectory=package
```
### :fire: Usage:
```bash
python -m jvd binary_file_to_decompile
```
If IDA Pro is not in the path, Ghidra jar will be downloaded and installed. 
During the first run, the required jar and JDK will be downloaded to `~/.jarv1s-ghidra` if needed.
### :star: Contributors:
- Steven Ding - Queen's Computing
- Christopher Bennett - Carleton University
- Miguel Garzon - University of Ottawa, Bell Canada
### 🌵 Used in `requirements.txt`:
```
git+https://github.com/L1NNA/JARV1S-Ghidra@master#subdirectory=pywrap
```
