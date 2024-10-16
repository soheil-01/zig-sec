const std = @import("std");
const builtin = @import("builtin");
const sec = @import("zig-sec");

const win = std.os.windows;

extern "user32" fn MessageBoxA(hWnd: ?win.HWND, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(win.WINAPI) i32;
extern "user32" fn MessageBoxW(hWnd: ?win.HWND, lpText: ?[*:0]const u16, lpCaption: ?[*:0]const u16, uType: u32) callconv(win.WINAPI) i32;

fn MyMessageBoxA(hWnd: ?win.HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(win.WINAPI) i32 {
    std.debug.print("[+] Intercepted MessageBoxA Call:\n", .{});
    std.debug.print("- Original Caption: {s}\n", .{lpCaption});
    std.debug.print("- Original Text: {s}\n", .{lpText});

    return MessageBoxW(
        hWnd,
        std.unicode.utf8ToUtf16LeStringLiteral("This MessageBox has been intercepted and modified."),
        std.unicode.utf8ToUtf16LeStringLiteral("Security Alert"),
        uType,
    );
}

pub fn main() !void {
    const user32 = win.kernel32.LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("user32.dll")) orelse return error.LoadLibraryWFailed;
    defer win.FreeLibrary(user32);

    const MessageBoxA_ptr = win.kernel32.GetProcAddress(user32, "MessageBoxA") orelse return error.GetProcAddressFailed;

    var function_hook = try sec.hook.FunctionHook.create(
        MessageBoxA_ptr,
        @constCast(@ptrCast(&MyMessageBoxA)),
    );

    _ = MessageBoxA(null, "This is the original MessageBoxA function.", "Original MessageBox", 0);

    function_hook.install();

    _ = MessageBoxA(null, "This text should not appear.", "You shouldn't see this caption", 0);

    try function_hook.uninstall();

    _ = MessageBoxA(null, "The hook has been removed. MessageBoxA is back to normal.", "Hook Removed", 0);
}
