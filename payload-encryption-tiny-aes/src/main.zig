const std = @import("std");
const c = @cImport({
    @cInclude("aes.h");
});

const KEYSIZE: u32 = 32;
const IVSIZE: u32 = 16;

fn paddBuffer(allocator: std.mem.Allocator, input_buffer: []const u8) ![]u8 {
    const padding_size: u8 = @intCast(16 - (input_buffer.len % 16));
    const padded_size = input_buffer.len + padding_size;

    const padded_buffer = try allocator.alloc(u8, padded_size);
    std.mem.copyForwards(u8, padded_buffer, input_buffer);

    // PKCS7 padding
    @memset(padded_buffer[input_buffer.len..], padding_size);

    return padded_buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const rand = std.crypto.random;

    var key: [KEYSIZE:0]u8 = undefined;
    rand.bytes(&key);

    var iv: [IVSIZE:0]u8 = undefined;
    rand.bytes(&iv);

    const data = [_]u8{ 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E, 0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E, 0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20, 0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67, 0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00 };

    const padded_buffer = try paddBuffer(allocator, &data);
    defer allocator.free(padded_buffer);

    std.debug.print("text: {x}\n", .{padded_buffer});

    var aes_ctx: c.AES_ctx = undefined;
    c.AES_init_ctx_iv(&aes_ctx, &key, &iv);

    const encrypted_buffer = try allocator.alloc(u8, padded_buffer.len);
    defer allocator.free(encrypted_buffer);
    @memcpy(encrypted_buffer, padded_buffer);

    c.AES_CBC_encrypt_buffer(&aes_ctx, encrypted_buffer.ptr, encrypted_buffer.len);
    std.debug.print("cipher text: {x}\n", .{encrypted_buffer});

    c.AES_init_ctx_iv(&aes_ctx, &key, &iv);

    const decrypted_buffer = try allocator.alloc(u8, encrypted_buffer.len);
    defer allocator.free(decrypted_buffer);
    @memcpy(decrypted_buffer, encrypted_buffer);

    c.AES_CBC_decrypt_buffer(&aes_ctx, decrypted_buffer.ptr, decrypted_buffer.len);
    std.debug.print("decrypted text: {x}\n", .{decrypted_buffer});
}
