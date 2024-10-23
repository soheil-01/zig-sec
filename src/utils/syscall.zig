const std = @import("std");
const win = @import("win.zig");

pub fn getSyscallNumberHellsGate(allocator: std.mem.Allocator, syscall_name: []const u8) !u16 {
    const h_ntdll = try win.getModuleHandleReplacement(allocator, "ntdll.dll") orelse return error.NtdllNotFound;
    const function_address: [*]const u8 = @ptrCast(try win.getProcAddressReplacement(h_ntdll, syscall_name) orelse return error.SyscallNotFound);

    var cw: u16 = 0;
    while (true) : (cw += 1) {
        // check if syscall, in this case we are too far
        if (function_address[cw] == 0x0f and function_address[cw + 1] == 0x05) break;

        // check if ret, in this case we are also probably too far
        if (function_address[cw] == 0xc3) break;

        // First opcodes should be:
        // mov r10, rcx
        // mov eax, <SSN>
        if (function_address[cw] == 0x4c and function_address[cw + 1] == 0x8b and function_address[cw + 2] == 0xd1 and function_address[cw + 3] == 0xb8 and function_address[cw + 6] == 0x00 and function_address[cw + 7] == 0x00) {
            const high = function_address[cw + 5];
            const low = function_address[cw + 4];

            return @as(u16, @intCast(high)) << 8 | @as(u16, @intCast(low));
        }
    }

    return error.SyscallNumberNotFound;
}

pub fn getSyscallNumberSysWhispers(syscall_name: []const u8) !u16 {
    _ = syscall_name;
}
