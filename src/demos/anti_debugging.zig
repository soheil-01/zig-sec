const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    std.debug.print("[!] isDebuggerPresent: {}\n", .{sec.anti_debugging.isDebuggerPresent()});
    std.debug.print("[!] isDebuggerPresent2: {}\n", .{sec.anti_debugging.isDebuggerPresent2()});
    std.debug.print("[!] isDebuggerPresent3: {}\n", .{sec.anti_debugging.isDebuggerPresent3()});
    std.debug.print("[!] ntQIPDebuggerCheck: {}\n", .{try sec.anti_debugging.ntQIPDebuggerCheck()});
    std.debug.print("[!] hardwareBpCheck: {}\n", .{try sec.anti_debugging.hardwareBpCheck()});
    std.debug.print("[!] blackListedProcessesCheck: {}\n", .{try sec.anti_debugging.blackListedProcessesCheck()});
    std.debug.print("[!] timeTickCheck1: {}\n", .{sec.anti_debugging.timeTickCheck1()});
    std.debug.print("[!] timeTickCheck2: {}\n", .{try sec.anti_debugging.timeTickCheck2()});
    std.debug.print("[!] outputDebugStringCheck: {}\n", .{sec.anti_debugging.outputDebugStringCheck()});

    _ = try std.io.getStdIn().reader().readByte();
}
