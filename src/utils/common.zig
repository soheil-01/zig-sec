const std = @import("std");

pub fn paddBuffer(allocator: std.mem.Allocator, input_buffer: []const u8, block_size: u8) ![]u8 {
    const padding_size: u8 = @intCast(block_size - (input_buffer.len % block_size));
    const padded_size = input_buffer.len + padding_size;

    const padded_buffer = try allocator.alloc(u8, padded_size);
    std.mem.copyForwards(u8, padded_buffer, input_buffer);

    @memset(padded_buffer[input_buffer.len..], 0);

    return padded_buffer;
}
