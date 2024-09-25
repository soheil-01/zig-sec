const std = @import("std");
const win = @import("zigwin32").everything;

const CreateMutexA = win.CreateMutexA;
const GetLastError = win.GetLastError;

fn isPayloadRunning() bool {
    const h_mutex = CreateMutexA(null, 0, "Maldev");
    if (h_mutex != null and GetLastError() == .ERROR_ALREADY_EXISTS) return true;
    return false;
}

pub fn main() !void {
    if (isPayloadRunning()) {
        std.debug.print("[!] Payload Is Already Running\n", .{});
    } else {
        std.debug.print("[!] Running Payload\n", .{});
    }

    _ = try std.io.getStdIn().reader().readByte();
}
