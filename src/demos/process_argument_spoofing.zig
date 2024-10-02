const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    _ = try sec.process.createArgSpoofedProcess(
        allocator,
        "cmd.exe",
        "benign argument",
        "/c calc.exe",
    );
}
