const std = @import("std");
const win = std.os.windows;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingDLL;

    std.debug.print("[i] Injecting \"{s}\" to the local process of Pid: {d}\n", .{ args[1], win.kernel32.GetCurrentProcessId() });

    const dll_path = try std.unicode.utf8ToUtf16LeAllocZ(allocator, args[1]);
    defer allocator.free(dll_path);

    if (win.kernel32.LoadLibraryW(dll_path) == null) {
        std.debug.print("[!] LoadLibraryW Failed With Error: {s}\n", .{@tagName(win.kernel32.GetLastError())});
        return error.LoadLibraryWFailed;
    }

    std.debug.print("[+] Done !\n", .{});
}
