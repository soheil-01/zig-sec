const std = @import("std");
const win = std.os.windows;

// from zigwin32 library
const PROCESS_ACCESS_RIGHTS = packed struct(u32) {
    TERMINATE: u1 = 0,
    CREATE_THREAD: u1 = 0,
    SET_SESSIONID: u1 = 0,
    VM_OPERATION: u1 = 0,
    VM_READ: u1 = 0,
    VM_WRITE: u1 = 0,
    DUP_HANDLE: u1 = 0,
    CREATE_PROCESS: u1 = 0,
    SET_QUOTA: u1 = 0,
    SET_INFORMATION: u1 = 0,
    QUERY_INFORMATION: u1 = 0,
    SUSPEND_RESUME: u1 = 0,
    QUERY_LIMITED_INFORMATION: u1 = 0,
    SET_LIMITED_INFORMATION: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    DELETE: u1 = 0,
    READ_CONTROL: u1 = 0,
    WRITE_DAC: u1 = 0,
    WRITE_OWNER: u1 = 0,
    SYNCHRONIZE: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

const PROCESS_ALL_ACCESS = PROCESS_ACCESS_RIGHTS{
    .TERMINATE = 1,
    .CREATE_THREAD = 1,
    .SET_SESSIONID = 1,
    .VM_OPERATION = 1,
    .VM_READ = 1,
    .VM_WRITE = 1,
    .DUP_HANDLE = 1,
    .CREATE_PROCESS = 1,
    .SET_QUOTA = 1,
    .SET_INFORMATION = 1,
    .QUERY_INFORMATION = 1,
    .SUSPEND_RESUME = 1,
    .QUERY_LIMITED_INFORMATION = 1,
    .SET_LIMITED_INFORMATION = 1,
    ._14 = 1,
    ._15 = 1,
    .DELETE = 1,
    .READ_CONTROL = 1,
    .WRITE_DAC = 1,
    .WRITE_OWNER = 1,
    .SYNCHRONIZE = 1,
};

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: PROCESS_ACCESS_RIGHTS,
    bInheritHandle: win.BOOL,
    dwProcessId: u32,
) callconv(win.WINAPI) ?win.HANDLE;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessId;

    const process_id = try std.fmt.parseInt(u32, args[1], 10);

    const process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
        const last_error = win.kernel32.GetLastError();
        std.debug.print("Failed to open process. Error: {}\n", .{last_error});
        return error.FailedToOpenProcess;
    };
    defer win.CloseHandle(process_handle);

    // do something with the handle
}
