const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const LoadLibraryA = win.LoadLibraryA;
const GetLastError = win.GetLastError;

const SLEEP_TIME = std.time.ns_per_s * 2;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingBasicEdrDllPath;

    const basic_edr_path = args[1];

    std.debug.print("[!] Check if NtProtectVirtualMemory is not touched\n", .{});
    std.time.sleep(SLEEP_TIME);

    _ = LoadLibraryA(basic_edr_path) orelse {
        std.debug.print("[!] LoadLibraryA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.LoadLibraryAFailed;
    };

    std.debug.print("[!] Check if NtProtectVirtualMemory is hooked\n", .{});
    std.time.sleep(SLEEP_TIME);

    try sec.unhook.disk.replaceNtdllTextSection(allocator);

    std.debug.print("[!] Check if NtProtectVirtualMemory is unhooked\n", .{});
    std.time.sleep(SLEEP_TIME);
}
