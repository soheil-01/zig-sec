const std = @import("std");
const win = @import("zigwin32").everything;
const common = @import("common.zig");

const HANDLE = std.os.windows.HANDLE;
const PROCESSINFOCLASS = std.os.windows.PROCESSINFOCLASS;
const PVOID = std.os.windows.PVOID;
const ULONG = std.os.windows.ULONG;
const NTSTATUS = std.os.windows.NTSTATUS;
const CONTEXT = win.CONTEXT;
const NtQueryInformationProcess = *const fn (
    process_handle: HANDLE,
    process_information_class: PROCESSINFOCLASS,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *ULONG,
) NTSTATUS;
const PROCESSENTRY32 = win.PROCESSENTRY32;
const LARGE_INTEGER = win.LARGE_INTEGER;

const IsDebuggerPresent = win.IsDebuggerPresent;
const GetThreadContext = win.GetThreadContext;
const GetLastError = win.GetLastError;
const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const CloseHandle = win.CloseHandle;
const Process32First = win.Process32First;
const Process32Next = win.Process32Next;
const GetTickCount64 = win.GetTickCount64;
const QueryPerformanceCounter = win.QueryPerformanceCounter;
const DebugBreak = win.DebugBreak;
const SetLastError = win.SetLastError;
const OutputDebugStringA = win.OutputDebugStringA;

pub fn isDebuggerPresent() bool {
    return IsDebuggerPresent() == 1;
}

pub fn isDebuggerPresent2() bool {
    const peb = std.os.windows.peb();
    return peb.BeingDebugged == 1;
}

pub fn isDebuggerPresent3() bool {
    const FLG_HEAP_ENABLE_TAIL_CHECK = 0x10;
    const FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
    const FLG_HEAP_VALIDATE_PARAMETERS = 0x40;

    const peb = std.os.windows.peb();

    return peb.NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
}

pub fn ntQIPDebuggerCheck() !bool {
    const QueryInformationProcess = try common.loadFunction(NtQueryInformationProcess, "ntdll.dll", "NtQueryInformationProcess");

    var is_debugger_present: u64 = 0;
    var return_len: u32 = 0;
    var status = QueryInformationProcess.func(
        std.os.windows.GetCurrentProcess(),
        .ProcessDebugPort,
        &is_debugger_present,
        @sizeOf(u64),
        &return_len,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] NtQueryInformationProcess Failed With Error: {s}\n", .{@tagName(status)});
        return error.NtQueryInformationProcessFailed;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
    if (is_debugger_present != 0) return true;

    var h_process_debug_object: u64 = 0;
    status = QueryInformationProcess.func(
        std.os.windows.GetCurrentProcess(),
        .ProcessDebugObjectHandle,
        &h_process_debug_object,
        @sizeOf(u64),
        &return_len,
    );
    if (status != .SUCCESS and status != .PORT_NOT_SET) {
        std.debug.print("[!] NtQueryInformationProcess Failed With Error: {s}\n", .{@tagName(status)});
        return error.NtQueryInformationProcessFailed;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
    return h_process_debug_object != 0;
}

pub fn hardwareBpCheck() !bool {
    var thread_context = std.mem.zeroes(CONTEXT);
    if (GetThreadContext(std.os.windows.GetCurrentThread(), &thread_context) == 0) {
        std.debug.print("[!] GetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetThreadContextFailed;
    }

    return thread_context.Dr0 != 0 or thread_context.Dr1 != 0 or thread_context.Dr2 != 0 or thread_context.Dr3 != 0;
}

pub fn blackListedProcessesCheck() !bool {
    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPPROCESS = 1 }, 0) orelse {
        std.debug.print("[!] CreateToolhelp32Snapshot Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateToolhelp32SnapshotFailed;
    };
    defer _ = CloseHandle(h_snapshot);

    var proc: PROCESSENTRY32 = undefined;

    if (Process32First(h_snapshot, &proc) == 0) {
        std.debug.print("[!] Process32First Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.Process32FirstFailed;
    }

    const black_list_debuggers = [_][]const u8{ "x64dbg.exe", "ida.exe", "ida64.exe", "VsDebugConsole.exe", "msvsmon.exe" };

    while (Process32Next(h_snapshot, &proc) != 0) {
        for (black_list_debuggers) |process_name| {
            if (std.ascii.eqlIgnoreCase(process_name, proc.szExeFile[0..process_name.len])) {
                return true;
            }
        }
    }

    return false;
}

pub fn timeTickCheck1() bool {
    const time1 = GetTickCount64();

    // OTHER CODE

    const time2 = GetTickCount64();

    return (time2 - time1) > 50;
}

pub fn timeTickCheck2() !bool {
    var time1 = std.mem.zeroes(LARGE_INTEGER);
    var time2 = std.mem.zeroes(LARGE_INTEGER);

    if (QueryPerformanceCounter(&time1) == 0) {
        std.debug.print("[!] QueryPerformanceCounter Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.QueryPerformanceCounterFailed;
    }

    // OTHER CODE

    if (QueryPerformanceCounter(&time2) == 0) {
        std.debug.print("[!] QueryPerformanceCounter Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.QueryPerformanceCounterFailed;
    }

    return time2.QuadPart - time1.QuadPart > 100_000;
}

pub fn outputDebugStringCheck() bool {
    OutputDebugStringA("Maldev");

    return GetLastError() == .NO_ERROR;
}
