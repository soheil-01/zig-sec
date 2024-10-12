const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const GetModuleHandleA = win.GetModuleHandleA;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const h_module1 = GetModuleHandleA("ntdll.dll") orelse return;
    const h_module2 = try sec.win.getModuleHandleReplacement(allocator, "ntdll.dll") orelse return;

    std.debug.print("[+] ntdll.dll 1: 0x{X}\n", .{@intFromPtr(h_module1)});
    std.debug.print("[+] ntdll.dll 2: 0x{X}\n", .{@intFromPtr(h_module2)});
}
