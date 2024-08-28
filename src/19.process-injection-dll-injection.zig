const std = @import("std");
const win = @import("zigwin32").everything;

const HANDLE = win.HANDLE;
const PROCESS_ALL_ACCESS = win.PROCESS_ALL_ACCESS;
const PROCESSENTRY32 = win.PROCESSENTRY32;
const INFINITE = win.INFINITE;

const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;
const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const Process32First = win.Process32First;
const Process32Next = win.Process32Next;
const OpenProcess = win.OpenProcess;
const VirtualAllocEx = win.VirtualAllocEx;
const WriteProcessMemory = win.WriteProcessMemory;
const CreateRemoteThread = win.CreateRemoteThread;
const VirtualFreeEx = win.VirtualFreeEx;
const GetModuleHandleW = win.GetModuleHandleW;
const GetProcAddress = win.GetProcAddress;
const WaitForSingleObject = win.WaitForSingleObject;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;
    if (args.len < 3) return error.MissingDLLPath;

    const process_name = args[1];
    const dll_path = args[2];

    const h_process = try getRemoteProcessHandle(process_name);
    try injectDLLToRemoteProcess(allocator, h_process, dll_path);
}

pub fn injectDLLToRemoteProcess(allocator: std.mem.Allocator, h_process: HANDLE, dll_path: []const u8) !void {
    const h_kernel32 = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse {
        std.debug.print("[!] GetModuleHandleW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetModuleHandleWFailed;
    };

    const load_library_w = GetProcAddress(h_kernel32, "LoadLibraryW") orelse {
        std.debug.print("[!] GetProcAddress Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetProcAddressFailed;
    };

    const address = VirtualAllocEx(
        h_process,
        null,
        dll_path.len,
        .{ .RESERVE = 1, .COMMIT = 1 },
        .{ .PAGE_READWRITE = 1 },
    ) orelse {
        std.debug.print("[!] VirtualAllocEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualAllocExFailed;
    };
    defer if (VirtualFreeEx(h_process, address, 0, .RELEASE) == 0) {
        std.debug.print("[!] VirtualFreeEx Failed With Error: {s}\n", .{@tagName(GetLastError())});
    };

    std.debug.print("[!] Memory Allocated For DLL_Path At: {*}\n", .{address});

    const dll_path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(dll_path_utf16);
    const dll_path_utf16_size = (dll_path_utf16.len + 1) * @sizeOf(u16);

    var numberOfBytesWritten: usize = undefined;
    if (WriteProcessMemory(h_process, address, dll_path_utf16.ptr, dll_path_utf16_size, &numberOfBytesWritten) == 0 or numberOfBytesWritten != dll_path_utf16_size) {
        std.debug.print("[!] WriteProcessMemory Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.WriteProcessMemoryFailed;
    }

    std.debug.print("[!] Successfully Written {d} Bytes\n", .{numberOfBytesWritten});

    const h_thread = CreateRemoteThread(h_process, null, 0, @ptrCast(load_library_w), address, 0, null) orelse {
        std.debug.print("[!] CreateRemoteThread Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateRemoteThreadFailed;
    };
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);

    std.debug.print("[+] Done\n", .{});
}

pub fn getRemoteProcessHandle(process_name: []const u8) !HANDLE {
    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPPROCESS = 1 }, 0) orelse {
        std.debug.print("[!] CreateToolhelp32Snapshot Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateToolhelp32SnapshotFailed;
    };
    defer _ = CloseHandle(h_snapshot);

    var proc: PROCESSENTRY32 = undefined;

    if (Process32First(h_snapshot, &proc) == 0) {
        std.debug.print("[!] Process32First Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.Process32FirstFailed;
    }

    while (Process32Next(h_snapshot, &proc) != 0) {
        if (std.ascii.eqlIgnoreCase(process_name, proc.szExeFile[0..process_name.len])) {
            const process_id = proc.th32ProcessID;
            const h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) orelse {
                std.debug.print("[!] OpenProcess Failed With Error: {s}\n", .{@tagName(GetLastError())});
                return error.OpenProcessFailed;
            };

            return h_process;
        }
    }

    return error.ProcessNotFound;
}
