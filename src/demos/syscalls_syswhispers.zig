const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;

const HANDLE = win.HANDLE;

fn NtTerminateProcess(allocator: std.mem.Allocator, process_handle: usize, exit_status: usize) !usize {
    const ssn = try sec.syscall.getSyscallNumberSysWhispers(allocator, "NtTerminateProcess");
    return sec.syscall.syscall2(ssn, process_handle, exit_status);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const process = try sec.process.openProcessByName(process_name);

    _ = try NtTerminateProcess(allocator, @intFromPtr(process.h_process), 0);
}
