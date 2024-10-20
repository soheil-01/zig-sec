const std = @import("std");
const builtin = @import("builtin");

const win = std.os.windows;

var TRAMPOLINE =
    if (builtin.cpu.arch == .x86_64)
    [_]u8{
        0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, 0x00
        0x41, 0xff, 0xe2, // jmp r10
    }
else
    [_]u8{
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00
        0xff, 0xe0, // jmp eax
    };

const TRAMPOLINE_SIZE = TRAMPOLINE.len;

pub const FunctionHook = struct {
    target_function: *anyopaque,
    replacement_function: *anyopaque,
    original_bytes: [TRAMPOLINE_SIZE]u8,
    original_protection: u32,
    is_installed: bool = false,

    pub fn create(target_function: *anyopaque, replacement_function: *anyopaque) !FunctionHook {
        var original_bytes: [TRAMPOLINE_SIZE]u8 = undefined;
        @memcpy(&original_bytes, @as([*]u8, @ptrCast(target_function))[0..TRAMPOLINE_SIZE]);

        var original_protection: u32 = 0;
        try win.VirtualProtect(
            target_function,
            TRAMPOLINE_SIZE,
            win.PAGE_EXECUTE_READWRITE,
            &original_protection,
        );

        return .{
            .target_function = target_function,
            .replacement_function = replacement_function,
            .original_bytes = original_bytes,
            .original_protection = original_protection,
        };
    }

    pub fn install(self: *FunctionHook) void {
        if (self.is_installed) return;

        var trampoline_copy = TRAMPOLINE;

        const replacement_address = @intFromPtr(self.replacement_function);

        if (builtin.cpu.arch == .x86_64) {
            std.mem.writeInt(u64, trampoline_copy[2..10], replacement_address, .little);
        } else {
            std.mem.writeInt(u32, trampoline_copy[1..5], replacement_address, .little);
        }

        @memcpy(
            @as([*]u8, @ptrCast(self.target_function))[0..TRAMPOLINE_SIZE],
            &trampoline_copy,
        );

        self.is_installed = true;
    }

    pub fn uninstall(self: *FunctionHook) !void {
        if (!self.is_installed) return;

        @memcpy(@as([*]u8, @ptrCast(self.target_function))[0..self.original_bytes.len], &self.original_bytes);

        var old_protection: u32 = 0;
        try win.VirtualProtect(
            self.target_function,
            TRAMPOLINE_SIZE,
            self.original_protection,
            &old_protection,
        );

        self.is_installed = false;
    }
};
