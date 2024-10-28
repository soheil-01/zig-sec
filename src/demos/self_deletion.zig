const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try sec.anti_debugging.deleteSelf(allocator);

    _ = try std.io.getStdIn().reader().readByte();
}
