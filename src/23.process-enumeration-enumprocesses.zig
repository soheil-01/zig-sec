const std = @import("std");
const win = @import("zigwin32").everything;

const HINSTANCE = win.HINSTANCE;
const HANDLE = win.HANDLE;

const OpenProcess = win.OpenProcess;
const EnumProcesses = win.K32EnumProcesses;
const EnumProcessModules = win.K32EnumProcessModules;
const GetModuleBaseNameA = win.K32GetModuleBaseNameA;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];

    try printProcesses();
    const h_process = try getRemoteProcessHandle(process_name) orelse return error.FailedToFindTheProcess;
    defer _ = CloseHandle(h_process);

    // do something with the process handle
}

fn printProcesses() !void {
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

    std.debug.print("[i] Number Of Processes Detected: {d}\n", .{num_of_pids});

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
        defer _ = CloseHandle(h_process);

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
        defer _ = CloseHandle(h_module.?);

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

        std.debug.print("[{d}] Process \"{s}\" - Of Pid: {d}\n", .{ i, process_name_buf[0..return_len3], process_id });
    }
}

fn getRemoteProcessHandle(process_name: []const u8) !?HANDLE {
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
