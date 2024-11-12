const std = @import("std");
const win = @import("win.zig");

const windows = std.os.windows;

pub fn syscall1(ssn: u32, arg1: usize) usize {
    return asm volatile (
        \\movq %rcx, %r10
        \\movl %[ssn], %eax
        \\syscall
        : [ret] "={rax}" (-> usize),
        : [ssn] "rm" (ssn),
          [arg1] "{rcx}" (arg1),
        : "r10", "r11"
    );
}

pub fn syscall2(ssn: u32, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\movq %rcx, %r10
        \\movl %[ssn], %eax
        \\syscall
        : [ret] "={rax}" (-> usize),
        : [ssn] "rm" (ssn),
          [arg1] "{rcx}" (arg1),
          [arg2] "{rdx}" (arg2),
        : "r10", "r11"
    );
}

pub fn getSyscallNumberTartarusGate(allocator: std.mem.Allocator, syscall_name: []const u8) !u16 {
    const h_ntdll = try win.getModuleHandleReplacement(allocator, "ntdll.dll") orelse return error.NtdllNotFound;
    const function_address = @intFromPtr(try win.getProcAddressReplacement(h_ntdll, syscall_name) orelse return error.SyscallNotFound);

    if (@as(*u8, @ptrFromInt(function_address)).* == 0x4c and
        @as(*u8, @ptrFromInt(function_address + 1)).* == 0x8b and
        @as(*u8, @ptrFromInt(function_address + 2)).* == 0xd1 and
        @as(*u8, @ptrFromInt(function_address + 3)).* == 0xb8 and
        @as(*u8, @ptrFromInt(function_address + 6)).* == 0x00 and
        @as(*u8, @ptrFromInt(function_address + 7)).* == 0x00)
    {
        const high = @as(*u8, @ptrFromInt(function_address + 5)).*;
        const low = @as(*u8, @ptrFromInt(function_address + 4)).*;

        return @as(u16, @intCast(high)) << 8 | @as(u16, @intCast(low));
    }

    // if hooked
    if (@as(*u8, @ptrFromInt(function_address)).* == 0xe9 or @as(*u8, @ptrFromInt(function_address + 3)).* == 0xe9) {
        for (1..256) |offset| {
            const index = offset * 32;

            // check neighboring syscall down
            if (@as(*u8, @ptrFromInt(function_address + index)).* == 0x4c and
                @as(*u8, @ptrFromInt(function_address + 1 + index)).* == 0x8b and
                @as(*u8, @ptrFromInt(function_address + 2 + index)).* == 0xd1 and
                @as(*u8, @ptrFromInt(function_address + 3 + index)).* == 0xb8 and
                @as(*u8, @ptrFromInt(function_address + 6 + index)).* == 0x00 and
                @as(*u8, @ptrFromInt(function_address + 7 + index)).* == 0x00)
            {
                const high = @as(*u8, @ptrFromInt(function_address + 5 + index)).*;
                const low = @as(*u8, @ptrFromInt(function_address + 4 + index)).*;

                return (@as(u16, @intCast(high)) << 8 | @as(u16, @intCast(low))) - @as(u16, @intCast(offset));
            }

            // check neighboring syscall up
            if (@as(*u8, @ptrFromInt(function_address - index)).* == 0x4c and
                @as(*u8, @ptrFromInt(function_address + 1 - index)).* == 0x8b and
                @as(*u8, @ptrFromInt(function_address + 2 - index)).* == 0xd1 and
                @as(*u8, @ptrFromInt(function_address + 3 - index)).* == 0xb8 and
                @as(*u8, @ptrFromInt(function_address + 6 - index)).* == 0x00 and
                @as(*u8, @ptrFromInt(function_address + 7 - index)).* == 0x00)
            {
                const high = @as(*u8, @ptrFromInt(function_address + 5 - index)).*;
                const low = @as(*u8, @ptrFromInt(function_address + 4 - index)).*;

                return (@as(u16, @intCast(high)) << 8 | @as(u16, @intCast(low))) + @as(u16, @intCast(offset));
            }
        }
    }

    return error.SyscallNumberNotFound;
}

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
        if (function_address[cw] == 0x4c and
            function_address[cw + 1] == 0x8b and
            function_address[cw + 2] == 0xd1 and
            function_address[cw + 3] == 0xb8 and
            function_address[cw + 6] == 0x00 and
            function_address[cw + 7] == 0x00)
        {
            const high = function_address[cw + 5];
            const low = function_address[cw + 4];

            return @as(u16, @intCast(high)) << 8 | @as(u16, @intCast(low));
        }
    }

    return error.SyscallNumberNotFound;
}

pub fn getSyscallNumberSysWhispers(allocator: std.mem.Allocator, syscall_name: []const u8) !u16 {
    const new_syscall_name = try allocator.alloc(u8, syscall_name.len);
    defer allocator.free(new_syscall_name);

    _ = std.mem.replace(u8, syscall_name, "Nt", "Zw", new_syscall_name);

    const h_ntdll = try win.getModuleHandleReplacement(allocator, "ntdll.dll") orelse return error.NtdllNotFound;
    const base_address: [*]const u8 = @ptrCast(h_ntdll);

    const export_directory = win.getExportDirectory(base_address) orelse return error.ExportDirectoryNotFound;

    const Entry = struct {
        name: []const u8,
        address: u32,
    };

    var entries = std.ArrayList(Entry).init(allocator);
    defer entries.deinit();

    for (0..export_directory.number_of_functions) |i| {
        const function_name: [*:0]const u8 = @alignCast(@ptrCast(base_address + export_directory.function_name_array[i]));
        const function_ordinal = export_directory.function_ordinal_array[i];
        const function_rva = export_directory.function_address_array[function_ordinal];

        if (std.mem.startsWith(u8, std.mem.span(function_name), "Zw")) {
            try entries.append(.{ .name = std.mem.span(function_name), .address = function_rva });
        }
    }

    const sortByAddress = struct {
        pub fn lessThan(_: void, a: Entry, b: Entry) bool {
            return a.address < b.address;
        }
    };

    std.mem.sort(Entry, entries.items, {}, sortByAddress.lessThan);

    for (entries.items, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, new_syscall_name)) return @intCast(i);
    }

    return error.SyscallNumberNotFound;
}
