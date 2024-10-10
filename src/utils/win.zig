const std = @import("std");
const win = @import("zigwin32").everything;

const FARPROC = win.FARPROC;
const HINSTANCE = win.HINSTANCE;
const IMAGE_DOS_HEADER = win.IMAGE_DOS_HEADER;
const IMAGE_FILE_HEADER = win.IMAGE_FILE_HEADER;
const IMAGE_OPTIONAL_HEADER_MAGIC = win.IMAGE_OPTIONAL_HEADER_MAGIC;
const IMAGE_NT_HEADERS32 = win.IMAGE_NT_HEADERS32;
const IMAGE_DATA_DIRECTORY = win.IMAGE_DATA_DIRECTORY;
const IMAGE_DLL_CHARACTERISTICS = win.IMAGE_DLL_CHARACTERISTICS;
const IMAGE_SUBSYSTEM = win.IMAGE_SUBSYSTEM;
const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    /// Deprecated
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};
const IMAGE_EXPORT_DIRECTORY = win.IMAGE_EXPORT_DIRECTORY;

const IMAGE_DOS_SIGNATURE = win.IMAGE_DOS_SIGNATURE;
const IMAGE_DIRECTORY_ENTRY_EXPORT = win.IMAGE_DIRECTORY_ENTRY_EXPORT;

pub fn getProcAddressReplacement(h_module: HINSTANCE, proc_name: []const u8) !?FARPROC {
    const base_address: [*]const u8 = @ptrCast(h_module);
    const dos_header: *const IMAGE_DOS_HEADER = @alignCast(@ptrCast(base_address));

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return null;

    const e_lfanew: usize = @intCast(dos_header.e_lfanew);

    const optional_header_magic: *const IMAGE_OPTIONAL_HEADER_MAGIC = @alignCast(@ptrCast(base_address + e_lfanew + @sizeOf(u32) + @sizeOf(IMAGE_FILE_HEADER)));

    const is_64bit: bool = if (optional_header_magic.* == .NT_OPTIONAL_HDR_MAGIC) true else false;

    var nt_headers_64: *const IMAGE_NT_HEADERS64 = undefined;
    var nt_headers_32: *const IMAGE_NT_HEADERS32 = undefined;
    const nt_headers_address = base_address + e_lfanew;
    if (is_64bit) nt_headers_64 = @alignCast(@ptrCast(nt_headers_address)) else nt_headers_32 = @alignCast(@ptrCast(nt_headers_address));

    const export_directory_rva = if (is_64bit) nt_headers_64.OptionalHeader.DataDirectory[@intFromEnum(IMAGE_DIRECTORY_ENTRY_EXPORT)].VirtualAddress else nt_headers_32.OptionalHeader.DataDirectory[@intFromEnum(IMAGE_DIRECTORY_ENTRY_EXPORT)].VirtualAddress;
    const export_directory: *const IMAGE_EXPORT_DIRECTORY = @alignCast(@ptrCast(base_address + export_directory_rva));

    const function_address_array: [*]const u32 = @alignCast(@ptrCast(base_address + @as(usize, @intCast(export_directory.AddressOfFunctions))));
    const function_name_array: [*]const u32 = @alignCast(@ptrCast(base_address + @as(usize, @intCast(export_directory.AddressOfNames))));
    const function_ordinal_array: [*]const u16 = @alignCast(@ptrCast(base_address + @as(usize, @intCast(export_directory.AddressOfNameOrdinals))));

    for (0..export_directory.NumberOfFunctions) |i| {
        const function_name: [*:0]const u8 = @alignCast(@ptrCast(base_address + function_name_array[i]));
        const function_ordinal = function_ordinal_array[i];
        const function_address = base_address + function_address_array[function_ordinal];

        if (std.mem.eql(u8, std.mem.span(function_name), proc_name)) return @constCast(@ptrCast(function_address));
    }

    return null;
}
