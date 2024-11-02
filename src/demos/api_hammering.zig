const std = @import("std");
const win = @import("zigwin32").everything;
const sec = @import("zig-sec");

const GetTickCount64 = win.GetTickCount64;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const t1 = GetTickCount64();
    try sec.anti_vm.apiHammering(allocator, 1000);
    const t2 = GetTickCount64();

    std.debug.print("[!] API Hammering Delayed Execution For : {d}ms\n", .{t2 - t1});
}
