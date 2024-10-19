const std = @import("std");
const win = @import("zigwin32").everything;

const WPARAM = win.WPARAM;
const LPARAM = win.LPARAM;
const LRESULT = win.LRESULT;
const HHOOK = win.HHOOK;
const MSG = win.MSG;

const WH_MOUSE_LL = win.WH_MOUSE_LL;
const WM_LBUTTONDOWN = win.WM_LBUTTONDOWN;
const WM_RBUTTONDOWN = win.WM_RBUTTONDOWN;
const WM_MBUTTONDOWN = win.WM_MBUTTONDOWN;

const SetWindowsHookExW = win.SetWindowsHookExW;
const UnhookWindowsHookEx = win.UnhookWindowsHookEx;
const CallNextHookEx = win.CallNextHookEx;
const CreateThread = win.CreateThread;
const WaitForSingleObject = win.WaitForSingleObject;
const GetMessageW = win.GetMessageW;
const GetLastError = win.GetLastError;

var h_mouse_hook: ?HHOOK = null;

fn hookCallback(code: i32, w_param: WPARAM, l_param: LPARAM) callconv(std.os.windows.WINAPI) LRESULT {
    if (w_param == WM_LBUTTONDOWN) {
        std.debug.print("[ # ] Left Mouse Click\n", .{});
    }

    if (w_param == WM_RBUTTONDOWN) {
        std.debug.print("[ # ] Right Mouse Click\n", .{});
    }

    if (w_param == WM_MBUTTONDOWN) {
        std.debug.print("[ # ] Middle Mouse Click\n", .{});
    }

    return CallNextHookEx(null, code, w_param, l_param);
}

fn mouseClickLogger() u32 {
    var msg: MSG = undefined;

    h_mouse_hook = SetWindowsHookExW(
        WH_MOUSE_LL,
        hookCallback,
        null,
        0,
    ) orelse {
        std.debug.print("[!] SetWindowsHookExW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return 0;
    };

    while (GetMessageW(&msg, null, 0, 0) == 1) {}

    return 1;
}

pub fn main() !void {
    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(&mouseClickLogger),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };

    _ = WaitForSingleObject(h_thread, 10000);

    if (h_mouse_hook != null and UnhookWindowsHookEx(h_mouse_hook.?) == 0) {
        std.debug.print("[!] UnhookWindowsHookEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.UnhookWindowsHookExFailed;
    }
}
