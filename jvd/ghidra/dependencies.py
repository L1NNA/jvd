from tqdm import tqdm
import subprocess
from jvd.resources import ResourceAbstract, require
import re
import platform
import os


class GhidraJar(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.default = 'https://github.com/L1NNA/JARV1S-Ghidra/releases/download/v0.0.1/jarv1s-ghidra.jar'
        self.check_update = False


class JDK(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jre_x64_linux_hotspot_17.0.7_7.tar.gz'
        self.windows = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jre_x64_windows_hotspot_17.0.7_7.zip'
        self.darwin = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jre_aarch64_mac_hotspot_17.0.7_7.tar.gz'
        self.default = self.linux
        self.check_update = False
        self.unpack = True

    def get(self):
        val = None
        try:
            version = subprocess.check_output(
                ['java', '-version'], stderr=subprocess.STDOUT)
            pattern = b'\"(\d+[\.]*\d+).*\"'
            val = re.search(pattern, version).groups()[0]
            val = float(val)
            if val >= 17:
                return 'java'
        except Exception as e:
            pass

        java = {
            'linux': 'jdk-17.0.7+7-jre/bin/java',
            'windows': 'jdk-17.0.7+7-jre/bin/java.exe',
            'darwin': 'jdk-17.0.7+7-jre/Contents/Home/bin/java',
        }[platform.system().lower()]
        root = super().get()
        java = os.path.join(root, java)
        return java
