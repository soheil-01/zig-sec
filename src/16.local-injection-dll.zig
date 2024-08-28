const std = @import("std");
const win = @import("zigwin32").everything;

const PVOID = *anyopaque;
const HINSTANCE = win.HINSTANCE;
const BOOL = win.BOOL;

const MessageBoxA = win.MessageBoxA;

const DLL_PROCESS_ATTACH = win.DLL_PROCESS_ATTACH;
const DLL_THREAD_ATTACH = win.DLL_THREAD_ATTACH;
const DLL_THREAD_DETACH = win.DLL_THREAD_DETACH;
const DLL_PROCESS_DETACH = win.DLL_PROCESS_DETACH;

pub export fn DllMain(hinstDLL: HINSTANCE, fdwReason: u32, lpReserved: PVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            _ = MessageBoxA(null, "DLL is loaded into the process", "Malware", .{});
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {},
        else => {},
    }
    return 1;
}
