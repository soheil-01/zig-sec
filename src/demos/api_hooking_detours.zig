const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;
const detours = sec.hook.detours;

extern "user32" fn MessageBoxA(hWnd: ?win.HWND, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(win.WINAPI) i32;

var g_MessageBoxA = &MessageBoxA;

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
    if (detours.detourTransactionBegin() != 0) {
        std.debug.print("[!] Detours Transaction Begin Failed\n", .{});
        return error.DetoursTransactionBeginFailed;
    }

    if (detours.detourUpdateThread(win.GetCurrentThread()) != 0) {
        std.debug.print("[!] Detours UpdateThread Failed\n", .{});
        return error.DetoursUpdateThreadFailed;
    }

    if (detours.detourAttach(@ptrCast(&g_MessageBoxA), &MyMessageBoxA) != 0) {
        std.debug.print("[!] Detours Attach Failed\n", .{});
        return error.DetoursAttachFailed;
    }

    if (detours.detourTransactionCommit() != 0) {
        std.debug.print("[!] Detours Transaction Commit Failed\n", .{});
        return error.DetoursTransactionCommitFailed;
    }
}

fn uninstallHook() !void {
    if (detours.detourTransactionBegin() != 0) {
        std.debug.print("[!] Detours Transaction Begin Failed\n", .{});
        return error.DetoursTransactionBeginFailed;
    }

    if (detours.detourUpdateThread(win.GetCurrentThread()) != 0) {
        std.debug.print("[!] Detours UpdateThread Failed\n", .{});
        return error.DetoursUpdateThreadFailed;
    }

    if (detours.detourDetach(@ptrCast(&g_MessageBoxA), MyMessageBoxA) != 0) {
        std.debug.print("[!] Detours Attach Failed\n", .{});
        return error.DetoursAttachFailed;
    }

    if (detours.detourTransactionCommit() != 0) {
        std.debug.print("[!] Detours Transaction Commit Failed\n", .{});
        return error.DetoursTransactionCommitFailed;
    }
}

pub fn main() !void {
    _ = MessageBoxA(null, "This is the original MessageBoxA function.", "Original MessageBox", 0);

    try installHook();

    _ = MessageBoxA(null, "This text should not appear.", "You shouldn't see this caption", 0);

    try uninstallHook();

    _ = MessageBoxA(null, "The hook has been removed. MessageBoxA is back to normal.", "Hook Removed", 0);
}
