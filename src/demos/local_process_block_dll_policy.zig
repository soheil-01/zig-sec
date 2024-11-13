const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const WaitForSingleObject = win.WaitForSingleObject;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 2) {
        std.debug.print("[!] Process Is Now Protected With The Block Dll Policy\n", .{});
        std.debug.print("[!] Running The Actual Payload\n", .{});

        _ = WaitForSingleObject(std.os.windows.GetCurrentProcess(), 10_000);
    } else {
        std.debug.print("[!] Creating Child Process With The Block Dll Policy\n", .{});
        const process_path = try std.fs.selfExePathAlloc(allocator);
        defer allocator.free(process_path);

        const process_path_with_argument = try std.mem.joinZ(allocator, " ", &.{ process_path, "STOP_ARG" });
        defer allocator.free(process_path_with_argument);

        _ = try sec.process.createProcessWithBlockDllPolicy(allocator, process_path_with_argument);
    }
}
