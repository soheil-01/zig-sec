const std = @import("std");
const win = @import("zigwin32").everything;

const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = win.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = win.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY;
const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 1 << 44;

const HANDLE = win.HANDLE;
const PROCESSENTRY32 = win.PROCESSENTRY32;
const HINSTANCE = win.HINSTANCE;
const SYSTEM_PROCESS_INFORMATION = win.SYSTEM_PROCESS_INFORMATION;
const STARTUPINFOA = win.STARTUPINFOA;
const PROCESS_INFORMATION = win.PROCESS_INFORMATION;
const PROCESS_CREATION_FLAGS = win.PROCESS_CREATION_FLAGS;
const STARTUPINFOEXA = win.STARTUPINFOEXA;
const LPPROC_THREAD_ATTRIBUTE_LIST = win.LPPROC_THREAD_ATTRIBUTE_LIST;
const PROCESS_BASIC_INFORMATION = win.PROCESS_BASIC_INFORMATION;
const PEB = win.PEB;
const RTL_USER_PROCESS_PARAMETERS = win.RTL_USER_PROCESS_PARAMETERS;

const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const Process32First = win.Process32First;
const Process32Next = win.Process32Next;
const OpenProcess = win.OpenProcess;
const EnumProcesses = win.K32EnumProcesses;
const EnumProcessModules = win.K32EnumProcessModules;
const GetModuleBaseNameA = win.K32GetModuleBaseNameA;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;
const NtQuerySystemInformation = win.NtQuerySystemInformation;
const CreateProcessA = win.CreateProcessA;
const InitializeProcThreadAttributeList = win.InitializeProcThreadAttributeList;
const UpdateProcThreadAttribute = win.UpdateProcThreadAttribute;
const DeleteProcThreadAttributeList = win.DeleteProcThreadAttributeList;
const ReadProcessMemory = win.ReadProcessMemory;
const WriteProcessMemory = win.WriteProcessMemory;
const NtQueryInformationProcess = win.NtQueryInformationProcess;
const ResumeThread = win.ResumeThread;
const HeapFree = win.HeapFree;
const GetProcessHeap = win.GetProcessHeap;

const ProcessInfo = struct {
    h_process: HANDLE,
    process_id: u32,
    h_thread: HANDLE,
};

pub fn openProcessByName(process_name: []const u8) !struct { h_process: HANDLE, process_id: u32 } {
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

pub fn openProcessByName2(process_name: []const u8) !?HANDLE {
    var process_ids: [1024]u32 = undefined;
    var return_len1: u32 = 0;
    if (EnumProcesses(
        @ptrCast(process_ids[0..]),
        @sizeOf(@TypeOf(process_ids)),
        &return_len1,
    ) == 0) {
        std.debug.print("[!] EnumProcesses Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.EnumProcessesFailed;
    }

    const num_of_pids = return_len1 / @sizeOf(u32);

    for (0..num_of_pids) |i| {
        const process_id = process_ids[i];

        if (process_id == 0) continue;

        const h_process = OpenProcess(
            .{ .VM_READ = 1, .QUERY_INFORMATION = 1 },
            0,
            process_id,
        ) orelse {
            switch (GetLastError()) {
                .ERROR_ACCESS_DENIED => continue,
                else => |err| {
                    std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(err)});
                    return error.OpenProcessFailed;
                },
            }
        };

        var h_module: ?HINSTANCE = null;
        var return_len2: u32 = 0;
        if (EnumProcessModules(
            h_process,
            &h_module,
            @sizeOf(HINSTANCE),
            &return_len2,
        ) == 0) {
            std.debug.print("[!] EnumProcessModules Failed [ At Pid: {d} ] With Error: {s}\n", .{ process_id, @tagName(GetLastError()) });
            return error.EnumProcessModulesFailed;
        }

        var process_name_buf: [256:0]u8 = undefined;
        const return_len3 = GetModuleBaseNameA(
            h_process,
            h_module.?,
            &process_name_buf,
            process_name_buf.len,
        );

        if (return_len3 == 0) {
            std.debug.print("[!] GetModuleBaseNameA Failed [ At Pid: {d} ] With Error: {s}\n", .{ process_id, @tagName(GetLastError()) });
            return error.GetModuleBaseNameAFailed;
        }

        if (std.ascii.eqlIgnoreCase(process_name, process_name_buf[0..return_len3])) {
            return h_process;
        }

        _ = CloseHandle(h_process);
    }

    return null;
}

pub fn openProcessByName3(allocator: std.mem.Allocator, process_name: []const u8) !?HANDLE {
    var return_len1: u32 = 0;
    _ = NtQuerySystemInformation(
        .ProcessInformation,
        null,
        0,
        &return_len1,
    );

    const system_proc_info = try allocator.alloc(u8, return_len1);
    defer allocator.free(system_proc_info);

    var return_len2: u32 = 0;
    const status = NtQuerySystemInformation(
        .ProcessInformation,
        system_proc_info.ptr,
        return_len1,
        &return_len2,
    );
    if (status != 0) {
        std.debug.print("[!] NtQuerySystemInformation Failed With Error: {d}\n", .{status});
        return error.NtQuerySystemInformationFailed;
    }

    var current_proc: *SYSTEM_PROCESS_INFORMATION = @ptrCast(@alignCast(system_proc_info));
    while (true) {
        if (current_proc.ImageName.Buffer != null and current_proc.UniqueProcessId != null) {
            const utf16_slice = current_proc.ImageName.Buffer.?[0 .. current_proc.ImageName.Length / 2];

            const utf8_slice = try std.unicode.utf16LeToUtf8Alloc(allocator, utf16_slice);
            defer allocator.free(utf8_slice);

            if (std.ascii.eqlIgnoreCase(utf8_slice, process_name)) {
                const process_id: u32 = @truncate(@intFromPtr(current_proc.UniqueProcessId.?));
                const h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
                    std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(GetLastError())});
                    return error.OpenProcessFailed;
                };
                return h_process;
            }
        }

        if (current_proc.NextEntryOffset == 0) break;
        current_proc = @ptrCast(@alignCast(@as([*]u8, @ptrCast(current_proc)) + current_proc.NextEntryOffset));
    }

    return null;
}

pub fn printProcesses(writer: anytype) !void {
    var process_ids: [1024]u32 = undefined;
    var return_len1: u32 = 0;
    if (EnumProcesses(
        @ptrCast(process_ids[0..]),
        @sizeOf(@TypeOf(process_ids)),
        &return_len1,
    ) == 0) {
        writer.print("[!] EnumProcesses Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.EnumProcessesFailed;
    }

    const num_of_pids = return_len1 / @sizeOf(u32);

    writer.print("[i] Number Of Processes Detected: {d}\n", .{num_of_pids});

    for (0..num_of_pids) |i| {
        const process_id = process_ids[i];

        if (process_id == 0) continue;

        const h_process = OpenProcess(
            .{ .VM_READ = 1, .QUERY_INFORMATION = 1 },
            0,
            process_id,
        ) orelse {
            switch (GetLastError()) {
                .ERROR_ACCESS_DENIED => continue,
                else => |err| {
                    writer.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(err)});
                    return error.OpenProcessFailed;
                },
            }
        };
        defer _ = CloseHandle(h_process);

        var h_module: ?HINSTANCE = null;
        var return_len2: u32 = 0;
        if (EnumProcessModules(
            h_process,
            &h_module,
            @sizeOf(HINSTANCE),
            &return_len2,
        ) == 0) {
            writer.print("[!] EnumProcessModules Failed [ At Pid: {d} ] With Error: {s}\n", .{ process_id, @tagName(GetLastError()) });
            return error.EnumProcessModulesFailed;
        }
        defer _ = CloseHandle(h_module.?);

        var process_name_buf: [256:0]u8 = undefined;
        const return_len3 = GetModuleBaseNameA(
            h_process,
            h_module.?,
            &process_name_buf,
            process_name_buf.len,
        );

        if (return_len3 == 0) {
            writer.print("[!] GetModuleBaseNameA Failed [ At Pid: {d} ] With Error: {s}\n", .{ process_id, @tagName(GetLastError()) });
            return error.GetModuleBaseNameAFailed;
        }

        writer.print("[{d}] Process \"{s}\" - Of Pid: {d}\n", .{ i, process_name_buf[0..return_len3], process_id });
    }
}

const ProcessCreationMode = enum {
    Suspended,
    Debugged,
};

pub fn createSuspendedProcess(allocator: std.mem.Allocator, process_name: []const u8, mode: ProcessCreationMode) !ProcessInfo {
    const win_dir = try std.process.getEnvVarOwned(allocator, "WINDIR");
    defer allocator.free(win_dir);

    const system_dir = try std.fmt.allocPrintZ(allocator, "{s}\\System32", .{win_dir});
    defer allocator.free(system_dir);

    const path = try std.fmt.allocPrintZ(allocator, "{s}\\{s}", .{ system_dir, process_name });
    defer allocator.free(path);

    var startup_info = std.mem.zeroes(STARTUPINFOA);
    var process_info: PROCESS_INFORMATION = undefined;

    const creation_mode: PROCESS_CREATION_FLAGS = switch (mode) {
        .Suspended => .{ .CREATE_SUSPENDED = 1, .CREATE_NO_WINDOW = 1 },
        .Debugged => .{ .DEBUG_PROCESS = 1, .CREATE_NO_WINDOW = 1 },
    };

    if (CreateProcessA(
        null,
        path,
        null,
        null,
        0,
        creation_mode,
        null,
        system_dir,
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
        .process_id = process_info.dwProcessId,
        .h_thread = process_info.hThread.?,
    };
}

// TODO: Got a segmentation fault error due to an unknown reason
fn createProcessWithAttribute(allocator: std.mem.Allocator, process_path: [*:0]u8, attribute: usize, value: *anyopaque, value_size: usize) !ProcessInfo {
    var thread_attr_list_size: usize = 0;
    _ = InitializeProcThreadAttributeList(
        null,
        1,
        0,
        &thread_attr_list_size,
    );
    const last_error = GetLastError();
    if (last_error != .ERROR_INSUFFICIENT_BUFFER) {
        std.debug.print("[!] InitializeProcThreadAttributeList Failed With Error: {s}\n", .{@tagName(last_error)});
        return error.InitializeProcThreadAttributeListFailed;
    }

    const thread_attr_list = try allocator.alignedAlloc(u8, @alignOf(LPPROC_THREAD_ATTRIBUTE_LIST), thread_attr_list_size);
    defer allocator.free(thread_attr_list);

    @memset(thread_attr_list, 0);

    const thread_attr_list_ptr: LPPROC_THREAD_ATTRIBUTE_LIST = @ptrCast(thread_attr_list.ptr);

    if (InitializeProcThreadAttributeList(
        thread_attr_list_ptr,
        1,
        0,
        &thread_attr_list_size,
    ) == 0) {
        std.debug.print("[!] InitializeProcThreadAttributeList Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.InitializeProcThreadAttributeListFailed;
    }
    defer DeleteProcThreadAttributeList(thread_attr_list_ptr);

    if (UpdateProcThreadAttribute(
        thread_attr_list_ptr,
        0,
        attribute,
        value,
        value_size,
        null,
        null,
    ) == 0) {
        std.debug.print("[!] UpdateProcThreadAttribute Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.UpdateProcThreadAttributeFailed;
    }

    var startup_info_ex = std.mem.zeroes(STARTUPINFOEXA);
    startup_info_ex.StartupInfo.cb = @sizeOf(STARTUPINFOEXA);
    startup_info_ex.lpAttributeList = thread_attr_list_ptr;

    var process_info: PROCESS_INFORMATION = undefined;

    if (CreateProcessA(
        null,
        process_path,
        null,
        null,
        0,
        .{ .EXTENDED_STARTUPINFO_PRESENT = 1 },
        null,
        "C:\\Windows\\System32",
        &startup_info_ex.StartupInfo,
        &process_info,
    ) == 0) {
        std.debug.print("[!] CreateProcessA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateProcessAFailed;
    }

    return .{
        .h_process = process_info.hProcess.?,
        .process_id = process_info.dwProcessId,
        .h_thread = process_info.hThread.?,
    };
}

pub fn createPPidSpoofedProcess(allocator: std.mem.Allocator, h_parent_process: HANDLE, process_name: []const u8) !ProcessInfo {
    const win_dir = try std.process.getEnvVarOwned(allocator, "WINDIR");
    defer allocator.free(win_dir);

    const path = try std.fmt.allocPrintZ(allocator, "{s}\\System32\\{s}", .{ win_dir, process_name });
    defer allocator.free(path);

    return createProcessWithAttribute(allocator, path, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, h_parent_process, @sizeOf(HANDLE));
}

pub fn createProcessWithBlockDllPolicy(allocator: std.mem.Allocator, process_path: [*:0]u8) !ProcessInfo {
    var policy: u64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    return createProcessWithAttribute(allocator, process_path, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, @sizeOf(u64));
}

pub fn readFromTargetProcess(h_process: HANDLE, base_address: *anyopaque, buf: *anyopaque, buf_len: usize) !void {
    var num_of_bytes_read: usize = 0;
    if (ReadProcessMemory(
        h_process,
        base_address,
        buf,
        buf_len,
        &num_of_bytes_read,
    ) == 0 or num_of_bytes_read != buf_len) {
        std.debug.print("[!] ReadProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.ReadProcessMemoryFailed;
    }
}

pub fn writeToTargetProcess(h_process: HANDLE, base_address: *anyopaque, buf: *anyopaque, buf_len: usize) !void {
    var num_of_bytes_written: usize = 0;
    if (WriteProcessMemory(
        h_process,
        base_address,
        buf,
        buf_len,
        &num_of_bytes_written,
    ) == 0 or num_of_bytes_written != buf_len) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }
}

pub fn createArgSpoofedProcess(allocator: std.mem.Allocator, application_name: []const u8, startup_args: []const u8, real_args: []const u8) !ProcessInfo {
    const startup_process_name = try std.mem.join(allocator, " ", &.{ application_name, startup_args });
    defer allocator.free(startup_process_name);

    const real_process_name = try std.mem.join(allocator, " ", &.{ application_name, real_args });
    defer allocator.free(real_process_name);

    const process_info = try createSuspendedProcess(
        allocator,
        startup_process_name,
        .Suspended,
    );

    var process_information: PROCESS_BASIC_INFORMATION = undefined;
    var return_len: u32 = 0;
    const status = NtQueryInformationProcess(
        process_info.h_process,
        .BasicInformation,
        @ptrCast(&process_information),
        @sizeOf(PROCESS_BASIC_INFORMATION),
        &return_len,
    );
    if (status != 0) {
        std.debug.print("[!] NtQueryInformationProcess Failed With Error: {d}\n", .{status});
        return error.NtQueryInformationProcessFailed;
    }

    var peb: PEB = undefined;
    try readFromTargetProcess(
        process_info.h_process,
        @ptrCast(process_information.PebBaseAddress.?),
        @ptrCast(&peb),
        @sizeOf(PEB),
    );
    defer _ = HeapFree(GetProcessHeap(), .{}, @ptrCast(&peb));

    var process_parameters: RTL_USER_PROCESS_PARAMETERS = undefined;
    try readFromTargetProcess(
        process_info.h_process,
        @ptrCast(peb.ProcessParameters.?),
        @ptrCast(&process_parameters),
        @sizeOf(RTL_USER_PROCESS_PARAMETERS) + 0xff,
    );
    defer _ = HeapFree(GetProcessHeap(), .{}, @ptrCast(&process_parameters));

    const real_process_name_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, real_process_name);
    defer allocator.free(real_process_name_utf16);

    try writeToTargetProcess(
        process_info.h_process,
        process_parameters.CommandLine.Buffer.?,
        @ptrCast(real_process_name_utf16.ptr),
        real_process_name_utf16.len * @sizeOf(u16) + 1,
    );

    const new_len: u16 = @as(u16, @intCast(application_name.len)) * @sizeOf(u16);
    try writeToTargetProcess(
        process_info.h_process,
        @ptrFromInt(@intFromPtr(peb.ProcessParameters.?) + @offsetOf(RTL_USER_PROCESS_PARAMETERS, "CommandLine")),
        @constCast(&new_len),
        @sizeOf(u16),
    );

    _ = ResumeThread(process_info.h_thread);

    return process_info;
}
