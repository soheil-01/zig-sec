const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingParentProcessName;

    const parent_process_name = args[1];

    const parent_process = try sec.process.openProcessByName(parent_process_name);

    const target_process = "\\??\\C:\\Windows\\System32\\RuntimeBroker.exe";
    const process_params = "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";
    const process_path = "C:\\Windows\\System32";

    const process = try sec.process.ntCreateUserProcess(
        target_process,
        process_params,
        process_path,
        parent_process.h_process,
    );

    std.debug.print("[!] Process Created Successfully With Process Id: {d}\n", .{process.process_id});
}
