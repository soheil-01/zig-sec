const std = @import("std");

pub const RC4 = struct {
    state: [256]u8 = undefined,
    i: u8 = 0,
    j: u8 = 0,

    pub fn init(key: []const u8) RC4 {
        var rc4 = RC4{};

        // Initialize state array
        for (0..256) |idx| rc4.state[idx] = @intCast(idx);

        // Key-Scheduling Algorithm (KSA)
        var j: u8 = 0;
        for (0..256) |i| {
            j = j +% rc4.state[i] +% key[i % key.len];
            rc4.swap(@intCast(i), j);
        }

        return rc4;
    }

    pub fn encrypt(rc4: *RC4, dest: []u8, src: []const u8) []u8 {
        std.debug.assert(dest.len >= src.len);

        for (src, 0..) |val, idx| dest[idx] = rc4.nextByte() ^ val;

        return dest[0..src.len];
    }

    pub const decrypt = encrypt;

    fn swap(rc4: *RC4, this: u8, that: u8) void {
        const tmp = rc4.state[this];
        rc4.state[this] = rc4.state[that];
        rc4.state[that] = tmp;
    }

    fn nextByte(rc4: *RC4) u8 {
        rc4.i +%= 1;
        rc4.j +%= rc4.state[rc4.i];
        rc4.swap(rc4.i, rc4.j);
        const t = rc4.state[rc4.i] +% rc4.state[rc4.j];

        return rc4.state[t];
    }
};
