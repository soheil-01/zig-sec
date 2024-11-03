const std = @import("std");
const win = @import("zigwin32").everything;

const GetLastError = win.GetLastError;
const MessageBoxA = win.MessageBoxA;
const IsDialogMessageA = win.IsDialogMessageA;

pub fn main() !void {
    const i: u32 = std.crypto.random.int(u32) % 0xff;

    // Impossible if-statement
    if (i > 255) {
        // Random benign WinAPIs
        _ = GetLastError();
        _ = MessageBoxA(null, null, null, .{});
        _ = IsDialogMessageA(null, null);
    }
}
