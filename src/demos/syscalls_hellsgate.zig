const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;

const HANDLE = win.HANDLE;
const NTSTATUS = win.NTSTATUS;

fn NtTerminateProcess(allocator: std.mem.Allocator, process_handle: HANDLE, exit_status: NTSTATUS) !NTSTATUS {
    const ssn = try sec.syscall.getSyscallNumberHellsGate(allocator, "NtTerminateProcess");

    return @enumFromInt(sec.syscall.syscall2(
        ssn,
        @intFromPtr(process_handle),
        @intFromEnum(exit_status),
    ));
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

    const status = try NtTerminateProcess(allocator, process.h_process, .SUCCESS);
    if (status != .SUCCESS) {
        std.debug.print("Error: {s}\n", .{@tagName(status)});
        return error.NtTerminateProcessFailed;
    }
}
