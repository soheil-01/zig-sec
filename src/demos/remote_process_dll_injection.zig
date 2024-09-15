const std = @import("std");
const sec = @import("zig-sec");

const CloseHandle = std.os.windows.CloseHandle;

const code_injection = sec.code_injection;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;
    if (args.len < 3) return error.MissingDLLPath;

    const process_name = args[1];
    const dll_path = args[2];

    const h_process = (try sec.process.openProcessByName(process_name)).h_process;
    defer CloseHandle(h_process);

    try code_injection.remote.loadDllIntoProcess(allocator, h_process, dll_path);
}
