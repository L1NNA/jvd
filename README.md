# JARV1S-Disassembler

 ![Build and Release Ghidra JAR](https://github.com/L1NNA/JARV1S-Disassembler/workflows/Build%20and%20Release%20Ghidra%20JAR/badge.svg) ![Ghidra Extractor for Capa](https://github.com/L1NNA/JARV1S-Disassembler/workflows/Ghidra%20Extractor%20for%20Capa/badge.svg) [![Source Lexer/AST/CPG-Parsers](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/src-lexer-ast.yml/badge.svg)](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/src-lexer-ast.yml) [![Decompilation and Capa Rule Matching](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/decompile-capa-rules.yml/badge.svg)](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/decompile-capa-rules.yml) [![Symbolic Execution](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/vex.yml/badge.svg)](https://github.com/L1NNA/JARV1S-Disassembler/actions/workflows/vex.yml) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?&maxAge=86400)

Universal disassembly generation and processing for JARV1S/Kam1n0

The package will detect if IDA Pro is available in the path. If not, it will download and use Ghidra.

### :rocket: Installation:
Required: Python 3+. [Optional: OpenJDK 13+]
```bash
# install from github:
pip install git+https://github.com/L1NNA/JARV1S-Ghidra@master

# install from offline installer:
python jvd_installer_windows.zip
```
### :fire: Usage:
Example:
```bash
jvd binary_file_to_decompile
```
Batch mode: (process files end with `.o` in the `bins` folder)
```bash
jvd bins --ext=.o
```
If IDA Pro is not in the path, Ghidra jar will be downloaded and installed. 
If not using the offline installer, during the first run, the required jar and JDK will be downloaded to `~/jv-dependences` if needed.
Options:
```bash
usage: jvd <file> [options]

positional arguments:
  file                  The binary file or the targeted path.

optional arguments:
  -h, --help            show this help message and exit
  --ext EXT             If the input is a folder, the file extension to
                        include. Default is all the files. Empty string will
                        select files without any `.`.
  --unpack              Unpack before disassembling.
  --cleanup             Clean up the temporary folders.
  --dis                 Disassemble all the applicable files.
  --dis-backend {ghidra}
                        The disassembler
  --dis-decompile       Decomiple the code (if IDA is chosen as disassembler,
                        it will use Ghidra to decompile and merge.
  --dis-capa            Analyze by capa
  --vex                 Extract vex code and execution path.
  --vex-tracelet TRACELET
                        For vex processing, extract tracelet (>0) rather than
                        full execution paths (-1).
  --vex-overlap         The tracelets overlap each other.
  --verbose {-1,0,1,2}
  --make                Make the installer for offline usage.

```
Packed binaries will be unapcked (in order) by:
```
- p7zip (zip, rar, tar, gzip, etc)
- upx (original version)
- un{i}packer
  - ASPack: Advanced commercial packer with a high compression ratio
  - FSG: Freeware, fast to unpack
  - MEW: Specifically designed for small binaries
  - MPRESS: Free, more complex packer
  - PEtite: Freeware packer, similar to ASPack
  - UPX: Cross-platform, open source packer (including modified UPX)
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
