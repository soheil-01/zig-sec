const std = @import("std");
const win = @import("zigwin32").everything;

const CreateEventA = win.CreateEventA;
const GetLastError = win.GetLastError;

fn isPayloadRunning() bool {
    const h_event = CreateEventA(null, 0, 0, "Maldev");
    if (h_event != null and GetLastError() == .ERROR_ALREADY_EXISTS) return true;
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
