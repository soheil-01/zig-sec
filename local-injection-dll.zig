const std = @import("std");
const win = std.os.windows;

const WINAPI = win.WINAPI;
const HINSTANCE = win.HINSTANCE;
const DWORD = win.DWORD;
const LPVOID = win.LPVOID;
const BOOL = win.BOOL;
const HWND = win.HWND;
const LPCSTR = win.LPCSTR;
const UINT = win.UINT;

extern "user32" fn MessageBoxA(hWnd: ?HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) callconv(WINAPI) i32;

const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;
const DLL_PROCESS_DETACH: DWORD = 0;

pub export fn DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpReserved: LPVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            _ = MessageBoxA(null, "DLL is loaded into the process", "Malware", 0);
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {},
        else => {},
    }
    return 1;
}
