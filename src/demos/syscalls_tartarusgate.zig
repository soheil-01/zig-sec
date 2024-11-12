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

    const syscall_number = try sec.syscall.getSyscallNumberHellsGate(allocator, "NtProtectVirtualMemory");

    std.debug.print("[!] NtProtectVirtualMemory Syscall Number Before Hook: 0x{x}\n", .{syscall_number});

    _ = LoadLibraryA(basic_edr_path) orelse {
        std.debug.print("[!] LoadLibraryA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.LoadLibraryAFailed;
    };
    std.time.sleep(SLEEP_TIME);

    _ = sec.syscall.getSyscallNumberHellsGate(allocator, "NtProtectVirtualMemory") catch |err| switch (err) {
        error.SyscallNumberNotFound => {
            std.debug.print("[!] Failed to get NtProtectVirtualMemory Syscall Number After Hook As Expected\n", .{});
        },
        else => return err,
    };

    const syscall_number2 = try sec.syscall.getSyscallNumberTartarusGate(allocator, "NtProtectVirtualMemory");
    std.debug.print("[!] NtProtectVirtualMemory Syscall Number Using TartarusGate: 0x{x}\n", .{syscall_number2});
}
