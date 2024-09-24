const std = @import("std");
const win = @import("zigwin32").everything;

const HINSTANCE = win.HINSTANCE;

const GetModuleHandleA = win.GetModuleHandleA;
const LoadLibraryA = win.LoadLibraryA;
const GetProcAddress = win.GetProcAddress;
const FreeLibrary = win.FreeLibrary;
const GetLastError = win.GetLastError;

pub fn paddBuffer(allocator: std.mem.Allocator, input_buffer: []const u8, block_size: u8) ![]u8 {
    const padding_size: u8 = @intCast(block_size - (input_buffer.len % block_size));
    const padded_size = input_buffer.len + padding_size;

    const padded_buffer = try allocator.alloc(u8, padded_size);
    std.mem.copyForwards(u8, padded_buffer, input_buffer);

    @memset(padded_buffer[input_buffer.len..], 0);

    return padded_buffer;
}

pub fn loadFunction(comptime T: type, module_name: [:0]const u8, function_name: [:0]const u8) !struct { func: T, h_module: HINSTANCE } {
    var h_module = GetModuleHandleA(module_name);

    if (h_module == null) {
        h_module = LoadLibraryA(module_name) orelse {
            std.debug.print("[!] LoadLibraryA Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.LoadLibraryAFailed;
        };
    }
    errdefer _ = FreeLibrary(h_module);

    const proc_address = GetProcAddress(h_module.?, function_name) orelse {
        std.debug.print("[!] GetProcAddress Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetProcAddressFailed;
    };

    return .{
        .func = @ptrCast(@constCast(proc_address)),
        .h_module = h_module.?,
    };
}
