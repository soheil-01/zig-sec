const std = @import("std");

pub fn djb2(input: []const u8) u32 {
    const INITIAL_HASH: u32 = 3731;
    const INITIAL_SEED = 7;

    var hash: u32 = INITIAL_HASH;
    for (input) |c| hash = (std.math.shl(u32, hash, INITIAL_SEED) +% hash) +% c;

    return hash;
}

pub fn jenkinsOneAtATime32(input: []const u8) u32 {
    const INITIAL_SEED = 7;

    var hash: u32 = 0;
    for (input) |c| {
        hash +%= c;
        hash +%= std.math.shl(u32, hash, INITIAL_SEED);
        hash ^= std.math.shr(u32, hash, 6);
    }

    hash +%= std.math.shl(u32, hash, 3);
    hash ^= std.math.shr(u32, hash, 11);
    hash +%= std.math.shl(u32, hash, 15);

    return hash;
}

pub fn loseLose(input: []const u8) u32 {
    const INITIAL_SEED = 2;

    var hash: u32 = 0;
    for (input) |c| {
        hash +%= c;
        hash *%= c + INITIAL_SEED;
    }

    return hash;
}

fn rotr32Sub(value: u32, count: u32) u32 {
    const mask: u5 = @typeInfo(u32).Int.bits - 1;
    const adjusted_count: i8 = @intCast(count & mask);

    return std.math.shr(u32, value, adjusted_count) | std.math.shl(u32, value, -adjusted_count & mask);
}

pub fn rotr32(input: []const u8) u32 {
    const INITIAL_SEED = 5;

    var value: u32 = 0;
    for (input) |c| value = c +% rotr32Sub(value, INITIAL_SEED);

    return value;
}
