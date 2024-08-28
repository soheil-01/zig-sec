const std = @import("std");
const win = @import("zigwin32").everything;

const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;

const OpenProcess = win.OpenProcess;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessId;

    const process_id = try std.fmt.parseInt(u32, args[1], 10);

    const process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
        std.debug.print("Failed to open process. Error: {s}\n", .{@tagName(GetLastError())});
        return error.FailedToOpenProcess;
    };
    defer _ = CloseHandle(process_handle);

    // do something with the handle
}
