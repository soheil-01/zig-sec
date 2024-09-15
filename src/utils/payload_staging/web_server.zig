const std = @import("std");
const win = @import("zigwin32").everything;

const INTERNET_FLAG_HYPERLINK = win.INTERNET_FLAG_HYPERLINK;
const INTERNET_FLAG_IGNORE_CERT_DATE_INVALID = win.INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
const INTERNET_OPTION_SETTINGS_CHANGED = win.INTERNET_OPTION_SETTINGS_CHANGED;

const GetLastError = win.GetLastError;
const InternetOpenW = win.InternetOpenW;
const InternetOpenUrlW = win.InternetOpenUrlW;
const InternetReadFile = win.InternetReadFile;
const InternetCloseHandle = win.InternetCloseHandle;
const InternetSetOptionW = win.InternetSetOptionW;

pub fn getPayloadFromUrl(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
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

pub fn getPayloadFromUrl2(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
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
