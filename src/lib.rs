// cSpell:enableCompoundWords
// cSpell:words tlhelp DWORD dwflag ctypes ctype winnt basetsd LPCVOID LPVOID PHANDLE LPCWSTR PLUID LUID baseaddr dll's nop's nopped

use winapi::um::tlhelp32::{TH32CS_SNAPPROCESS, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32W, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Module32FirstW, Module32NextW};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, HANDLE};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::ctypes::c_void;
use wio::wide::FromWide;
use std::mem::{zeroed, size_of, MaybeUninit};
use std::ffi::OsString;



/// takes process name as &str and returns corresponding process ID
///
/// # Examples
///
/// ```
/// let process_name = "FarCry5.exe";
/// let process_id = find_pid_by_name(process_name).unwrap_or_else(|e| {panic!("{}",e)});
/// println!("{} PID: {}", process_name, process_id);
/// ```
#[cfg(target_os="windows")]
pub fn find_pid_by_name(name: &str) -> Result<u32, String> {
    let snap_handle = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};                             //DWORD dwflag TH32CS_SNAPMODULE32 and pid 0 tells api to create system snapshot of all processes
    if snap_handle == INVALID_HANDLE_VALUE {                                                                //if snapshot handle == {0xffffffffffffffff as *mut ctypes::c_void}
        return Err(format!("Invalid system snapshot handle: {:?}", snap_handle))                            //return error
    }

    let mut process_entry: PROCESSENTRY32W = unsafe {zeroed()};                                             //A pointer to a PROCESSENTRY32W structure required by Process32FirstW
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;                                             //set dwSize to size of PROCESSENTRY32W or it will fail

    match unsafe {Process32FirstW(snap_handle, &mut process_entry)} {                                       //takes snapshot handle, pointer to PROCESSENTRY32W struct and writes first process in snapshot to PROCESSENTRY32W struct
        1 => {                                                                                              //if Process32FirstW returns Ok()
            let mut success : i32 = 1;                                                                      //set success flag to 1
            while success == 1 {                                                                            //while Process32FirstW returns Ok()
                let process_name = OsString::from_wide(&process_entry.szExeFile);                           //converts process name in process_entry.szExeFile from array to ctype string
                match process_name.into_string() {                                                          //convert from ctypes string into rust string
                    Ok(s) => {                                                                              //if conversion success
                        if s.replace("\u{0}","") == name {                                                  //remove junk from process_name and if process_name == target name
                            unsafe {CloseHandle(snap_handle)};                                              //close snapshot handle
                            return Ok(process_entry.th32ProcessID)                                          //return Ok(PID)
                        }
                    },
                    Err(_) => {                                                                             //if conversion failed
                        println!("Error converting process name for PID {}", process_entry.th32ProcessID);  //print failed message
                    }
                }
                success = unsafe {Process32NextW(snap_handle, &mut process_entry)};                         //iterate through process snapshot, updating process_entry data and capture return value into success
            }
            unsafe {CloseHandle(snap_handle)};                                                              //if none matched, close snapshot handle
            Err(format!("Process \"{}\" not found", name))                                                  //return error
        },
        _ => {
            unsafe {CloseHandle(snap_handle)};                                                              //if none matched, close snapshot handle
            Err(format!("Process \"{}\" not found", name))                                                  //return error
        }
    }
}



/// takes process pid and target dll name and returns target dll's BaseAddr\
/// needs admin rights
///
/// # Example
///
/// ```
/// let process_id = 1829;
/// let module_name = "FC_m64.dll";
/// let base_addr = get_module_base_by_name(process_id, module_name).unwrap_or_else(|e| {panic!("{}",e)});
/// println!("{} BaseAddr: 0x{:X}",module_name ,base_addr);
/// ```
#[cfg(target_os="windows")]
pub fn get_module_base_by_name(pid: u32, name: &str) -> Result<u64, String> {
    let snap_handle = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)};        //tells api to create snapshot of 32&64 bit modules in target process
    if snap_handle == INVALID_HANDLE_VALUE {                                                                //if snapshot handle == {0xffffffffffffffff as *mut ctypes::c_void}
        return Err(format!("Invalid module snapshot handle: {:?} (try running as admin)", snap_handle))    //return error
    }

    let mut module_entry: MODULEENTRY32W = unsafe {zeroed()};                                               //A pointer to a MODULEENTRY32W structure required by Module32FirstW
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;                                               //set dwSize to size of MODULEENTRY32W or it will fail

    match unsafe {Module32FirstW(snap_handle, &mut module_entry)} {                                         //takes snapshot handle, pointer to MODULEENTRY32W struct and writes first module in snapshot to MODULEENTRY32W struct
        1 => {                                                                                              //if Module32FirstW returns Ok()
            let mut success : i32 = 1;                                                                      //set success flag to 1
            while success == 1 {                                                                            //while Module32FirstW returns Ok()
                let module_name = OsString::from_wide(&module_entry.szModule);                              //converts module name in module_entry.szModule from array to ctype string
                match module_name.into_string() {                                                           //convert from ctypes string into rust string
                    Ok(s) => {                                                                              //if conversion success
                        if s.replace("\u{0}","") == name {                                                  //remove junk from module_name and if module_name == target name
                            unsafe {CloseHandle(snap_handle)};                                              //close snapshot handle
                            return Ok(module_entry.modBaseAddr as u64)                                      //return Ok(BaseAddr)
                        }
                    },
                    Err(_) => {                                                                             //if conversion failed
                        println!("Error converting module name for PID {}", module_entry.th32ModuleID);     //print failed message
                    }
                }
                success = unsafe {Module32NextW(snap_handle, &mut module_entry)};                           //iterate through module snapshot, updating module_entry data and capture return value into success
            }
            unsafe {CloseHandle(snap_handle)};                                                              //if none matched, close snapshot handle
            Err(format!("Module \"{}\" not found", name))                                                   //return error
        },
        _ => {
            unsafe {CloseHandle(snap_handle)};                                                              //if none matched, close snapshot handle
            Err(format!("Module \"{}\" not found", name))                                                   //return error
        }
    }
}



/// gets handle to target process with all possible permissions\
/// needs admin rights
///
/// # Example
///
/// ```
/// let process_id = 1829;
/// let process_handle = get_handle_all(process_id).unwrap_or_else(|e| {panic!("{}",e)});
/// ```
#[cfg(target_os="windows")]
pub fn get_handle_all(pid: u32) -> Result<HANDLE, String> {
    let handle = unsafe{OpenProcess(PROCESS_ALL_ACCESS, 0, pid)};                       //takes the desired access, InheritHandle flag (false for us), and  pid. returns handle to process
    match handle as usize {
        0x0 => Err("Unable to get process handle (try running as admin)".to_string()),  //if handle is null return error
        _ => Ok(handle),                                                                //else return handle
    }
}



/// read [size] bytes at [addr] in [handle]
///
/// # Example
/// ```
/// let health_call_addr = 0x7FFF7D33B0B4;
/// let bytes = read_memory(process_handle, health_call_addr, 3).unwrap_or_else(|e| {panic!("{}",e)});
/// if bytes == vec!(0xFF, 0x50, 0x30) {println!("Read successful: {:X?}",bytes)}
/// else {println!("Error: Read bytes contain unexpected values:{:X?}",bytes); exit(5);}
/// ```
#[cfg(target_os="windows")]
pub fn read_memory(handle: HANDLE, addr: u64, size: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let mut buffer = Vec::with_capacity(size);                                                                                  //creates empty buffer with capacity of <size>
        buffer.set_len(size);                                                                                                       //sets buffer len to <size>
        let mut bytes_read = MaybeUninit::uninit().assume_init();                                                                   //creates uninitalized var to capture len of bytes read
        match ReadProcessMemory(handle, addr as LPCVOID, buffer.as_mut_ptr() as *mut c_void, size, &mut bytes_read as *mut usize) { //takes handle, baseaddr, buffer to write to, size, and var to write read len to
            1 => {                                                                                                                  //if success
                if bytes_read == size {Ok(buffer)}                                                                                  //if correct amount of bytes read return buffer
                else {Err(format!("Error: read {} bytes instead of {} at {:X}", bytes_read, size, addr))}                           //else return error
            },
            _ => Err(format!("Error reading memory at {:X}", addr))                                                                 //if error reading return error
        }
    }
}



/// write [buffer] at [addr] in [handle]\
/// returns 0 if success
///
/// # Example
///
/// ```
/// let health_call_addr = 0x7FFF7D33B0B4;
/// let mut buffer = vec!(0x90;3);
/// write_memory(process_handle, health_call_addr, &mut buffer).unwrap_or_else(|e| {panic!("{}",e)});
/// ```
#[cfg(target_os="windows")]
pub fn write_memory(handle: HANDLE, addr: u64, buffer: &mut Vec<u8>) -> Result<u8,String> {
    unsafe {
        let mut bytes_wrote = MaybeUninit::uninit().assume_init();                                                                              //creates uninitalized var to capture len of bytes written
        match WriteProcessMemory(handle, addr as LPVOID, buffer.as_mut_ptr() as *mut c_void, buffer.len(), &mut bytes_wrote as *mut usize) {    //takes handle, baseaddr, bytes to write, size to write, and var to return len of bytes written
            1 => {                                                                                                                              //if success
                if bytes_wrote == buffer.len() {Ok(0)}                                                                                          //if correct amount of bytes written, return Ok
                else {Err(format!("Error: wrote {} bytes instead of {} at {:X}", bytes_wrote, buffer.len(), addr))}                             //else return error
            },
            _ => Err(format!("Error writing to memory at {:X}", addr))                                                                          //if error writing return error
        }
    }
}



/// Reads len [target_bytes] at [base_addr]+[offset] in [handle].\
/// If read bytes match target_bytes, writes nop's at offset.
/// If read bytes are nop, writes target_bytes at offset
/// Returns 0 if successful
/// 
/// # Example
/// 
/// ```
/// target_bytes = vec!(0xFF, 0x50, 0x30);
/// let target_offset = 0x86AB0B4;
/// toggle_nop(process_handle, base_addr, target_offset, target_bytes).unwrap_or_else(|e| {panic!("{}",e)});
/// ```
pub fn toggle_nop(process_handle: *mut std::ffi::c_void, base_addr: u64, offset: u64, target_bytes: Vec<u8>) -> Result<u8,String>{
    let target_addr = base_addr+offset;                                                             //calculates target offset
    let mut nop = vec!(0x90;target_bytes.len());                                                    //creates nopped bytes
    let read_bytes = read_memory(process_handle, target_addr, target_bytes.len())?;                 //reads target_bytes.len() memory at offset
    if &read_bytes == target_bytes {                                                                //if bytes haven't been nopped
        write_memory(process_handle, target_addr, &mut nop)?;                                       //write nopped bytes at offset
    } else if read_bytes == nop {                                                                   //else if have been nopped
        write_memory(process_handle, target_addr, &mut target_bytes)?;                              //write target bytes at offset
    } else {return Err(format!("Error: Read bytes contained unexpected values:{:X?}",read_bytes))}  //if bytes don't match target_bytes or nopped bytes, return error
    Ok(0)
}