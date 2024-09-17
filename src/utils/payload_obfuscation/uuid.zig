const std = @import("std");
const win = @import("zigwin32").everything;
const common = @import("../common.zig");

const assert = std.debug.assert;

const Guid = @import("zigwin32").zig.Guid;
const PSTR = win.PSTR;

const UuidFromStringA = win.UuidFromStringA;

fn generateUUid(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, p: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{X:0>2}{X:0>2}{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p });
}

pub fn obfuscate(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    const padded_shell_code = try common.paddBuffer(allocator, shell_code, 16);
    defer allocator.free(padded_shell_code);

    var uuid_array = try std.ArrayList([:0]const u8).initCapacity(allocator, padded_shell_code.len / 16);
    errdefer freeUUidArray(allocator, uuid_array.items);

    var i: usize = 0;
    while (i < padded_shell_code.len) : (i += 16) {
        const uuid = try generateUUid(allocator, padded_shell_code[i], padded_shell_code[i + 1], padded_shell_code[i + 2], padded_shell_code[i + 3], padded_shell_code[i + 4], padded_shell_code[i + 5], padded_shell_code[i + 6], padded_shell_code[i + 7], padded_shell_code[i + 8], padded_shell_code[i + 9], padded_shell_code[i + 10], padded_shell_code[i + 11], padded_shell_code[i + 12], padded_shell_code[i + 13], padded_shell_code[i + 14], padded_shell_code[i + 15]);
        uuid_array.appendAssumeCapacity(uuid);
    }

    return uuid_array.toOwnedSlice();
}

pub fn deobfuscate(allocator: std.mem.Allocator, uuid_array: []const [:0]const u8) ![]u8 {
    var shell_code = try std.ArrayList(u8).initCapacity(allocator, uuid_array.len * 16);
    errdefer shell_code.deinit();

    for (uuid_array) |string_uuid| {
        var uuid: Guid = undefined;

        const status = UuidFromStringA(@ptrCast(@constCast(string_uuid)), &uuid);
        if (@intFromEnum(status) != 0) {
            std.debug.print("UUIDDeobfuscation Failed With Error: {s}\n", .{@tagName(status)});
            return error.UUIDDeobfuscationFailed;
        }

        shell_code.appendSliceAssumeCapacity(&uuid.Bytes);
    }

    return shell_code.toOwnedSlice();
}

pub fn printUUidArray(writer: anytype, uuid_array: []const [:0]const u8) !void {
    try writer.writeAll("UUID Array: [");
    for (uuid_array, 0..) |uuid, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{uuid});
    }
    try writer.writeAll("]\n");
}

pub fn freeUUidArray(allocator: std.mem.Allocator, uuid_array: [][:0]const u8) void {
    for (uuid_array) |uuid| allocator.free(uuid);
    allocator.free(uuid_array);
}
