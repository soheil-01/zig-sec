const std = @import("std");
const win = std.os.windows;

pub fn main() !void {
    // zig win uses pseudo handles for the current process and thread
    const h_process = win.GetCurrentProcess();
    const h_thread = win.GetCurrentThread();

    const last_error1 = win.kernel32.GetLastError();
    const last_error2: u16 = @truncate(@intFromPtr(win.teb().Reserved2[0]));

    std.debug.print("[+] Current Process: {d}\n", .{@intFromPtr(h_process)});
    std.debug.print("[+] Current Thread: {d}\n", .{@intFromPtr(h_thread)});

    std.debug.print("[+] Last Error 1: {d}\n", .{@intFromEnum(last_error1)});
    std.debug.print("[+] Last Error 2: {d}\n", .{last_error2});
}
