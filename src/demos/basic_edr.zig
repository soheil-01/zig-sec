const std = @import("std");
const win = @import("zigwin32").everything;
const sec = @import("zig-sec");

const minhook = sec.hook.minhook;

const DLL_PROCESS_ATTACH = win.DLL_PROCESS_ATTACH;
const DLL_THREAD_ATTACH = win.DLL_THREAD_ATTACH;
const DLL_THREAD_DETACH = win.DLL_THREAD_DETACH;
const DLL_PROCESS_DETACH = win.DLL_PROCESS_DETACH;

const PAGE_EXECUTE_READWRITE = std.os.windows.PAGE_EXECUTE_READWRITE;
const PAGE_EXECUTE_READ = std.os.windows.PAGE_EXECUTE_READ;

const PVOID = *anyopaque;
const HINSTANCE = win.HINSTANCE;
const BOOL = win.BOOL;
const HANDLE = win.HANDLE;
const NTSTATUS = win.NTSTATUS;

const CreateThread = win.CreateThread;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;
const MessageBoxA = win.MessageBoxA;
const ExitProcess = win.ExitProcess;

var g_NtProtectVirtualMemory: *const fn (processHandle: HANDLE, baseAddress: PVOID, numberOfBytesToProtect: *u32, newAccessProtection: u32, oldAccessProtection: *u32) NTSTATUS = undefined;

fn HookedNtProtectVirtualMemory(processHandle: HANDLE, baseAddress: PVOID, numberOfBytesToProtect: *u32, newAccessProtection: u32, oldAccessProtection: *u32) NTSTATUS {
    std.debug.print("[#] NTProtectVirtualMemory At [ 0x{d} ] Of Size [ {d} ]\n", .{ @intFromPtr(baseAddress), numberOfBytesToProtect.* });

    // dump memory + terminate
    if ((newAccessProtection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        std.debug.print("\t\t\t<<<!>>> [DETECTED] PAGE_EXECUTE_READWRITE [DETECTED] <<<!>>> \n", .{});
        blockExecution(@ptrCast(baseAddress), numberOfBytesToProtect.*, true);
    }

    // dump memory + continue
    if ((newAccessProtection & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ) {
        std.debug.print("\t\t\t<<<!>>> [DETECTED] PAGE_EXECUTE_READ [DETECTED] <<<!>>> \n", .{});
        blockExecution(@ptrCast(baseAddress), numberOfBytesToProtect.*, false);
    }

    return g_NtProtectVirtualMemory(processHandle, baseAddress, numberOfBytesToProtect, newAccessProtection, oldAccessProtection);
}

fn installHook() !void {
    if (minhook.initialize() != .MH_OK) {
        std.debug.print("[!] MinHook Initialize Failed\n", .{});
        return error.MinHookInitializeFailed;
    }

    if (minhook.createHookApi(
        std.unicode.utf8ToUtf16LeStringLiteral("NTDLL.DLL"),
        "NtProtectVirtualMemory",
        &HookedNtProtectVirtualMemory,
        @ptrCast(&g_NtProtectVirtualMemory),
    ) != .MH_OK) {
        std.debug.print("[!] MinHook CreateHook Failed\n", .{});
        return error.MinHookCreateHookFailed;
    }

    if (minhook.enableHook(minhook.MH_ALL_HOOKS) != .MH_OK) {
        std.debug.print("[!] MinHook EnableHook Failed\n", .{});
        return error.MinHookEnableHookFailed;
    }
}

fn uninstallHook() !void {
    if (minhook.disableHook(minhook.MH_ALL_HOOKS) != .MH_OK) {
        std.debug.print("[!] MinHook DisableHook Failed\n", .{});
        return error.MinHookDisableHookFailed;
    }

    if (minhook.uninitialize() != .MH_OK) {
        std.debug.print("[!] MinHook UninstallHook Failed\n", .{});
        return error.MinHookUninstallHookFailed;
    }
}

fn blockExecution(address: [*]const u8, size: u32, terminate: bool) void {
    std.debug.print("\n\t------------------------------------[ MEMORY DUMP ]------------------------------------\n\n", .{});
    for (0..@min(size, 256)) |i| {
        if (i % 16 == 0) std.debug.print("\n\t\t", .{});
        std.debug.print(" {X:0>2}", .{address[i]});
    }
    std.debug.print("\n\n\t------------------------------------[ MEMORY DUMP ]------------------------------------\n\n", .{});

    if (terminate) {
        _ = MessageBoxA(null, "Terminating The Process ...", "EDR", .{});
        ExitProcess(1);
    }
}

pub export fn DllMain(hinstDLL: HINSTANCE, fdwReason: u32, lpReserved: PVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;

    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            const h_thread = CreateThread(null, 0, @ptrCast(&installHook), null, .{}, null) orelse {
                std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return 0;
            };
            _ = CloseHandle(h_thread);
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {
            uninstallHook() catch return 0;
        },
        else => {},
    }
    return 1;
}
