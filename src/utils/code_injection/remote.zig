const std = @import("std");
const win = @import("zigwin32").everything;

const HANDLE = win.HANDLE;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const INFINITE = win.INFINITE;

const VirtualAllocEx = win.VirtualAllocEx;
const VirtualFreeEx = win.VirtualFreeEx;
const WriteProcessMemory = win.WriteProcessMemory;
const VirtualProtectEx = win.VirtualProtectEx;
const GetLastError = win.GetLastError;
const CreateRemoteThread = win.CreateRemoteThread;
const CloseHandle = win.CloseHandle;
const WaitForSingleObject = win.WaitForSingleObject;
const GetModuleHandleA = win.GetModuleHandleA;
const GetProcAddress = win.GetProcAddress;

pub fn allocateMemory(comptime T: type, h_process: HANDLE, data: []const T) !*anyopaque {
    const data_size = (data.len + 1) * @sizeOf(T);

    const region = VirtualAllocEx(
        h_process,
        null,
        data_size,
        .{ .RESERVE = 1, .COMMIT = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };

    var num_of_bytes_written: usize = undefined;
    if (WriteProcessMemory(
        h_process,
        region,
        data.ptr,
        data_size,
        &num_of_bytes_written,
    ) == 0 or num_of_bytes_written != data_size) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    return region;
}

pub fn allocateExecutableMemory(comptime T: type, h_process: HANDLE, data: []const T) !*anyopaque {
    const region = try allocateMemory(T, h_process, data);

    const data_size = (data.len + 1) * @sizeOf(T);

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtectEx(
        h_process,
        region,
        data_size,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }

    return region;
}

pub fn freeVirtualMemory(h_process: HANDLE, region: *anyopaque) void {
    _ = VirtualFreeEx(h_process, region, 0, .RELEASE);
}

pub fn executeInNewThread(h_process: HANDLE, start_address: LPTHREAD_START_ROUTINE, parameter: ?*anyopaque) !void {
    const h_thread = CreateRemoteThread(
        h_process,
        null,
        0,
        start_address,
        parameter,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}

pub fn loadDllIntoProcess(allocator: std.mem.Allocator, h_process: HANDLE, dll_path: []const u8) !void {
    const h_kernel32 = GetModuleHandleA("kernel32.dll") orelse {
        std.debug.print("[!] GetModuleHandleW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetModuleHandleWFailed;
    };

    const load_library_w = GetProcAddress(h_kernel32, "LoadLibraryW") orelse {
        std.debug.print("[!] GetProcAddress Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetProcAddressFailed;
    };

    const dll_path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(dll_path_utf16);

    const remote_dll_path_ptr = try allocateMemory(u16, h_process, dll_path_utf16);
    defer freeVirtualMemory(h_process, remote_dll_path_ptr);

    try executeInNewThread(h_process, @ptrCast(load_library_w), remote_dll_path_ptr);
}

pub fn injectShellCodeToProcess(h_process: HANDLE, shell_code: []const u8) !void {
    const shell_code_region = try allocateExecutableMemory(u8, h_process, shell_code);
    defer freeVirtualMemory(h_process, shell_code_region);

    try executeInNewThread(h_process, @ptrCast(shell_code_region), null);
}
