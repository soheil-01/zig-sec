const std = @import("std");
const sec = @import("zig-sec");

const key = sec.payload_encryption.key;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const hint = 12;

    const protected_key = try key.generateProtectedKey(allocator, hint, 10);
    defer allocator.free(protected_key);

    std.debug.print("[!] Protected Key: {x}\n", .{protected_key});

    const brute_force_key = try key.bruteForceProtectedKey(allocator, hint, protected_key);
    defer allocator.free(brute_force_key);

    std.debug.print("[!] Brute Force Decrypted Key: {x}\n", .{brute_force_key});
}
