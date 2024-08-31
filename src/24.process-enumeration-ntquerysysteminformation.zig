const std = @import("std");
const win = @import("zigwin32").everything;

const HANDLE = win.HANDLE;
const SYSTEM_PROCESS_INFORMATION = win.SYSTEM_PROCESS_INFORMATION;
const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;

const NtQuerySystemInformation = win.NtQuerySystemInformation;
const OpenProcess = win.OpenProcess;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const proc_name = args[1];

    const h_process = try getRemoteProcessHandle(allocator, proc_name) orelse return error.ProcessNotFound;
    defer _ = CloseHandle(h_process);
}

fn getRemoteProcessHandle(allocator: std.mem.Allocator, proc_name: []const u8) !?HANDLE {
    var return_len1: u32 = 0;
    _ = NtQuerySystemInformation(
        .ProcessInformation,
        null,
        0,
        &return_len1,
    );

    const system_proc_info = try allocator.alloc(u8, return_len1);
    defer allocator.free(system_proc_info);

    var return_len2: u32 = 0;
    const status = NtQuerySystemInformation(
        .ProcessInformation,
        system_proc_info.ptr,
        return_len1,
        &return_len2,
    );
    if (status != 0) {
        std.debug.print("[!] NtQuerySystemInformation Failed With Error: {d}\n", .{status});
        return error.NtQuerySystemInformationFailed;
    }

    var current_proc: *SYSTEM_PROCESS_INFORMATION = @ptrCast(@alignCast(system_proc_info));
    while (true) {
        if (current_proc.ImageName.Buffer != null and current_proc.UniqueProcessId != null) {
            const utf16_slice = current_proc.ImageName.Buffer.?[0 .. current_proc.ImageName.Length / 2];

            const utf8_slice = try std.unicode.utf16LeToUtf8Alloc(allocator, utf16_slice);
            defer allocator.free(utf8_slice);

            if (std.ascii.eqlIgnoreCase(utf8_slice, proc_name)) {
                const process_id: u32 = @truncate(@intFromPtr(current_proc.UniqueProcessId.?));
                const h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
                    std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(GetLastError())});
                    return error.OpenProcessFailed;
                };
                return h_process;
            }
        }

        if (current_proc.NextEntryOffset == 0) break;
        current_proc = @ptrCast(@alignCast(@as([*]u8, @ptrCast(current_proc)) + current_proc.NextEntryOffset));
    }

    return null;
}
