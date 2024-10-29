const std = @import("std");
const win = @import("zigwin32").everything;

const HKEY_LOCAL_MACHINE = win.HKEY_LOCAL_MACHINE;
const KEY_READ = win.KEY_READ;

const SYSTEM_INFO = win.SYSTEM_INFO;
const MEMORYSTATUSEX = win.MEMORYSTATUSEX;
const HKEY = win.HKEY;
const HMONITOR = win.HMONITOR;
const HDC = win.HDC;
const RECT = win.RECT;
const LPARAM = win.LPARAM;
const BOOL = win.BOOL;
const MONITORINFO = win.MONITORINFO;

const GetSystemInfo = win.GetSystemInfo;
const GlobalMemoryStatusEx = win.GlobalMemoryStatusEx;
const RegOpenKeyExA = win.RegOpenKeyExA;
const RegQueryInfoKeyA = win.RegQueryInfoKeyA;
const GetLastError = win.GetLastError;
const EnumDisplayMonitors = win.EnumDisplayMonitors;
const GetMonitorInfoW = win.GetMonitorInfoW;

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

fn resolutionCallback(
    h_monitor: ?HMONITOR,
    _: ?HDC,
    _: ?*RECT,
    data: usize,
) callconv(std.os.windows.WINAPI) BOOL {
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
