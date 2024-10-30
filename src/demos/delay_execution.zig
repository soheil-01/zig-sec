const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    std.debug.print("[!] delayExecutionViaWFSO: {}\n", .{sec.delay.delayExecutionViaWFSO(6000)});
    std.debug.print("[!] delayExecutionViaMWFMOEx: {}\n", .{sec.delay.delayExecutionViaMWFMOEx(6000)});
    std.debug.print("[!] delayExecutionViaNtWFSO: {}\n", .{sec.delay.delayExecutionViaNtWFSO(6000)});
    std.debug.print("[!] delayExecutionViaNtDE: {}\n", .{sec.delay.delayExecutionViaNtDE(6000)});
}
