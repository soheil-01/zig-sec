const std = @import("std");
const win = @import("zigwin32").everything;
const common = @import("common.zig");

const WAIT_FAILED = win.WAIT_FAILED;
const STATUS_TIMEOUT = win.STATUS_TIMEOUT;

const HANDLE = win.HANDLE;
const BOOLEAN = win.BOOLEAN;
const LARGE_INTEGER = win.LARGE_INTEGER;
const NTSTATUS = win.NTSTATUS;

const CreateEventA = win.CreateEventA;
const GetTickCount64 = win.GetTickCount64;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;
const WaitForSingleObject = win.WaitForSingleObject;
const MsgWaitForMultipleObjectsEx = win.MsgWaitForMultipleObjectsEx;

pub fn delayExecutionViaWFSO(milli_seconds: usize) bool {
    const h_event = CreateEventA(null, 0, 0, null) orelse {
        std.debug.print("[!] CreateEventA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    };
    defer _ = CloseHandle(h_event);

    const t0 = GetTickCount64();
    if (WaitForSingleObject(h_event, @intCast(milli_seconds)) == @intFromEnum(WAIT_FAILED)) {
        std.debug.print("[!] WaitForSingleObject Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    }
    const t1 = GetTickCount64();

    return t1 - t0 >= milli_seconds;
}

pub fn delayExecutionViaMWFMOEx(milli_seconds: usize) bool {
    const h_event = CreateEventA(null, 0, 0, null) orelse {
        std.debug.print("[!] CreateEventA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    };
    defer _ = CloseHandle(h_event);

    const t0 = GetTickCount64();
    if (MsgWaitForMultipleObjectsEx(
        1,
        @ptrCast(&h_event),
        @intCast(milli_seconds),
        .{ .HOTKEY = 1 },
        .{},
    ) == @intFromEnum(WAIT_FAILED)) {
        std.debug.print("[!] MsgWaitForMultipleObjectsEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    }
    const t1 = GetTickCount64();

    return t1 - t0 >= milli_seconds;
}

const NtWaitForSingleObject = *const fn (handle: HANDLE, alertable: BOOLEAN, timeout: *LARGE_INTEGER) NTSTATUS;

pub fn delayExecutionViaNtWFSO(milli_seconds: isize) bool {
    const pNtWaitForSingleObject = common.loadFunction(NtWaitForSingleObject, "ntdll.dll", "NtWaitForSingleObject") catch return false;
    var delay_interval = LARGE_INTEGER{ .QuadPart = -milli_seconds * 10_000 };
    const h_event = CreateEventA(null, 0, 0, null) orelse {
        std.debug.print("[!] CreateEventA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    };
    defer _ = CloseHandle(h_event);

    const t0 = GetTickCount64();
    const status = pNtWaitForSingleObject.func(
        h_event,
        0,
        &delay_interval,
    );
    if (status != 0 and status != STATUS_TIMEOUT) {
        std.debug.print("[!] NtWaitForSingleObject Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    }
    const t1 = GetTickCount64();

    return t1 - t0 >= milli_seconds;
}

const NtDelayExecution = *const fn (alertable: BOOLEAN, delay_interval: *LARGE_INTEGER) NTSTATUS;

pub fn delayExecutionViaNtDE(milli_seconds: isize) bool {
    const pNtDelayExecution = common.loadFunction(NtDelayExecution, "ntdll.dll", "NtDelayExecution") catch return false;
    var delay_interval = LARGE_INTEGER{ .QuadPart = -milli_seconds * 10_000 };

    const t0 = GetTickCount64();
    const status = pNtDelayExecution.func(
        0,
        &delay_interval,
    );
    if (status != 0 and status != STATUS_TIMEOUT) {
        std.debug.print("[!] NtDelayExecution Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return false;
    }
    const t1 = GetTickCount64();

    return t1 - t0 >= milli_seconds;
}
