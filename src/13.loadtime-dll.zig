const win = @import("zigwin32").everything;

const MessageBoxA = win.MessageBoxA;

export fn printInfo() void {
    _ = MessageBoxA(null, "Hello!", "Zig", .{});
}
