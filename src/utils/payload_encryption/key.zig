const std = @import("std");

pub fn generateProtectedKey(allocator: std.mem.Allocator, hint: u8, len: usize) ![]u8 {
    const b = std.crypto.random.int(u8);

    const key = try allocator.alloc(u8, len);
    defer allocator.free(key);

    key[0] = hint;
    std.crypto.random.bytes(key[1..]);

    const protected_key = try allocator.alloc(u8, len);
    for (0..len) |i| protected_key[i] = (key[i] +% @as(u8, @intCast(i))) ^ b;

    return protected_key;
}

pub fn bruteForceProtectedKey(allocator: std.mem.Allocator, hint: u8, protected_key: []const u8) ![]u8 {
    var b: u8 = 0;
    while (b < 256) : (b += 1) if (protected_key[0] ^ b == hint) break;

    const key = try allocator.alloc(u8, protected_key.len);
    for (0..protected_key.len) |i| key[i] = (protected_key[i] ^ b) -% @as(u8, @intCast(i));

    return key;
}
