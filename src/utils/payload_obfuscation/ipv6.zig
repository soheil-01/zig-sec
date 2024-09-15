const std = @import("std");
const win = @import("zigwin32").everything;
const assert = std.debug.assert;

const PSTR = win.PSTR;
const IN6_ADDR = win.IN6_ADDR;

const RtlIpv6StringToAddressA = win.RtlIpv6StringToAddressA;

fn generateIpv6(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, p: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}", .{ a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p });
}

pub fn obfuscate(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    assert(shell_code.len % 16 == 0);

    var ipv6_array = try std.ArrayList([:0]const u8).initCapacity(allocator, shell_code.len / 16);
    errdefer freeIpv6Array(allocator, ipv6_array.items);

    var i: usize = 0;
    while (i < shell_code.len) : (i += 16) {
        const ipv6 = try generateIpv6(allocator, shell_code[i], shell_code[i + 1], shell_code[i + 2], shell_code[i + 3], shell_code[i + 4], shell_code[i + 5], shell_code[i + 6], shell_code[i + 7], shell_code[i + 8], shell_code[i + 9], shell_code[i + 10], shell_code[i + 11], shell_code[i + 12], shell_code[i + 13], shell_code[i + 14], shell_code[i + 15]);
        ipv6_array.appendAssumeCapacity(ipv6);
    }

    return ipv6_array.toOwnedSlice();
}

pub fn deobfuscate(allocator: std.mem.Allocator, ipv6_array: [][:0]const u8) ![]u8 {
    var shell_code = try std.ArrayList(u8).initCapacity(allocator, ipv6_array.len * 16);
    errdefer shell_code.deinit();

    for (ipv6_array) |ipv6| {
        var addr: IN6_ADDR = undefined;
        var terminator: ?PSTR = null;

        const status = RtlIpv6StringToAddressA(ipv6, &terminator, &addr);
        if (status != 0) {
            std.debug.print("IPv6Deobfuscation Failed With Error Code: {d}\n", .{status});
            return error.IPv6DeobfuscationFailed;
        }

        shell_code.appendSliceAssumeCapacity(&addr.u.Byte);
    }

    return shell_code.toOwnedSlice();
}

pub fn printIpv6Array(writer: anytype, ipv6_array: []const [:0]const u8) !void {
    try writer.writeAll("IPv6 Array: [");
    for (ipv6_array, 0..) |ipv6, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{ipv6});
    }
    try writer.writeAll("]\n");
}

pub fn freeIpv6Array(allocator: std.mem.Allocator, ipv6_array: [][:0]const u8) void {
    for (ipv6_array) |ipv6| allocator.free(ipv6);
    allocator.free(ipv6_array);
}
