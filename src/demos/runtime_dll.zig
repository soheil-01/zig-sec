const std = @import("std");

const win = std.os.windows;

export fn printInfo() void {
    printInfoInternal() catch |err| {
        std.debug.print("Error: {any}\n", .{err});
    };
}

fn printInfoInternal() !void {
    const user32 = try win.LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("user32.dll"));
    defer win.FreeLibrary(user32);

    const messageBoxA = win.kernel32.GetProcAddress(user32, "MessageBoxA") orelse return error.FunctionNotFound;
    const MessageBoxA: *const fn (?win.HWND, win.LPCSTR, win.LPCSTR, win.UINT) callconv(win.WINAPI) i32 = @ptrCast(messageBoxA);

    _ = MessageBoxA(null, "Hello!", "Zig", 0);
}
