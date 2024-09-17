const std = @import("std");
const win = @import("zigwin32").everything;

const assert = std.debug.assert;

const GetEnvironmentVariableA = win.GetEnvironmentVariableA;
const GetLastError = win.GetLastError;

pub fn getEnvironmentVariable(name: [:0]const u8, buf: [:0]u8) ![]u8 {
    const win_dir_len = GetEnvironmentVariableA(name, buf, @intCast(buf.len));

    assert(win_dir_len <= buf.len);
    if (win_dir_len == 0) {
        std.debug.print("[!] GetEnvironmentVariableA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetEnvironmentVariableAFailed;
    }

    return buf[0..win_dir_len];
}
