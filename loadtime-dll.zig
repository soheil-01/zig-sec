const std = @import("std");
const win = std.os.windows;

extern "user32" fn MessageBoxA(hWnd: ?win.HWND, lpText: win.LPCSTR, lpCaption: win.LPCSTR, uType: win.UINT) callconv(win.WINAPI) i32;

export fn printInfo() void {
    _ = MessageBoxA(null, "Hello!", "Zig", 0);
}
