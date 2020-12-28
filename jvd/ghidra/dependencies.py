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
        self.check_update = True


class JDK(ResourceAbstract):
    def __init__(self):
        super().__init__()
        self.linux = 'https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.9.1%2B1/OpenJDK11U-jre_x64_linux_hotspot_11.0.9.1_1.tar.gz'
        self.windows = 'https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.9.1%2B1/OpenJDK11U-jre_x64_windows_hotspot_11.0.9.1_1.zip'
        self.darwin = 'https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.9.1%2B1/OpenJDK11U-jre_x64_mac_hotspot_11.0.9.1_1.tar.gz'
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
            if val >= 11:
                return 'java'
        except Exception as e:
            pass

        java = {
            'linux': 'jdk-11.0.9.1+1-jre/bin/java',
            'windows': 'jdk-11.0.9.1+1-jre/bin/java.exe',
            'darwin': 'jdk-11.0.9.1+1-jre/jdk/Contents/Home/bin/java',
        }[platform.system().lower()]
        root = super().get()
        java = os.path.join(root, java.format(self.jdk))
        if not os.path.exists(java):
            super().get()
        return java
