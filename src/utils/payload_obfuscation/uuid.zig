const std = @import("std");
const win = @import("zigwin32").everything;

const assert = std.debug.assert;

const Guid = @import("zigwin32").zig.Guid;
const PSTR = win.PSTR;

const UuidFromStringA = win.UuidFromStringA;

fn generateUUid(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, p: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{X:0>2}{X:0>2}{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p });
}

pub fn obfuscate(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    assert(shell_code.len % 16 == 0);

    var uuid_array = try std.ArrayList([:0]const u8).initCapacity(allocator, shell_code.len / 16);
    errdefer freeUUidArray(allocator, uuid_array.items);

    var i: usize = 0;
    while (i < shell_code.len) : (i += 16) {
        const uuid = try generateUUid(allocator, shell_code[i], shell_code[i + 1], shell_code[i + 2], shell_code[i + 3], shell_code[i + 4], shell_code[i + 5], shell_code[i + 6], shell_code[i + 7], shell_code[i + 8], shell_code[i + 9], shell_code[i + 10], shell_code[i + 11], shell_code[i + 12], shell_code[i + 13], shell_code[i + 14], shell_code[i + 15]);
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
