const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;

const OpenProcessA = win.OpenProcess;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingParentProcessId;

    const parent_process_id = try std.fmt.parseInt(u32, args[1], 10);

    const h_parent_process = OpenProcessA(PROCESS_ALL_ACCESS, 0, parent_process_id) orelse {
        std.debug.print("[!] OpenProcessA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.OpenProcessAFailed;
    };
    defer _ = CloseHandle(h_parent_process);

    const process_info = try sec.process.createPPidSpoofedProcess(allocator, h_parent_process, "notepad.exe");

    std.debug.print("[!] Process Created With Pid: {d}\n", .{process_info.process_id});

    _ = try std.io.getStdIn().reader().readByte();
}
