const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;
const minhook = sec.hook.minhook;

extern "user32" fn MessageBoxA(hWnd: ?win.HWND, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(win.WINAPI) i32;

var g_MessageBoxA: *const fn (hWnd: ?win.HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(win.WINAPI) i32 = undefined;

fn MyMessageBoxA(hWnd: ?win.HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(win.WINAPI) i32 {
    std.debug.print("[+] Intercepted MessageBoxA Call:\n", .{});
    std.debug.print("- Original Caption: {s}\n", .{lpCaption});
    std.debug.print("- Original Text: {s}\n", .{lpText});

    return g_MessageBoxA(
        hWnd,
        "This MessageBox has been intercepted and modified.",
        "Security Alert",
        uType,
    );
}

fn installHook() !void {
    if (minhook.initialize() != .MH_OK) {
        std.debug.print("[!] MinHook Initialize Failed\n", .{});
        return error.MinHookInitializeFailed;
    }

    if (minhook.createHook(&MessageBoxA, &MyMessageBoxA, @ptrCast(&g_MessageBoxA)) != .MH_OK) {
        std.debug.print("[!] MinHook CreateHook Failed\n", .{});
        return error.MinHookCreateHookFailed;
    }

    if (minhook.enableHook(&MessageBoxA) != .MH_OK) {
        std.debug.print("[!] MinHook EnableHook Failed\n", .{});
        return error.MinHookEnableHookFailed;
    }
}

fn uninstallHook() !void {
    if (minhook.disableHook(&MessageBoxA) != .MH_OK) {
        std.debug.print("[!] MinHook DisableHook Failed\n", .{});
        return error.MinHookDisableHookFailed;
    }

    if (minhook.uninitialize() != .MH_OK) {
        std.debug.print("[!] MinHook UninstallHook Failed\n", .{});
        return error.MinHookUninstallHookFailed;
    }
}

pub fn main() !void {
    _ = MessageBoxA(null, "This is the original MessageBoxA function.", "Original MessageBox", 0);

    try installHook();

    _ = MessageBoxA(null, "This text should not appear.", "You shouldn't see this caption", 0);

    try uninstallHook();

    _ = MessageBoxA(null, "The hook has been removed. MessageBoxA is back to normal.", "Hook Removed", 0);
}
