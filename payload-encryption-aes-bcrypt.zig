const std = @import("std");
const windows = std.os.windows;
const NTSTATUS = windows.NTSTATUS;
const WINAPI = windows.WINAPI;
const LPSTR = windows.LPSTR;

const KEYSIZE: u32 = 32;
const IVSIZE: u32 = 16;

// from zigwin32 library

const BCRYPT_HANDLE = isize;
const BCRYPT_KEY_HANDLE = BCRYPT_HANDLE;
const BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS = packed struct(u32) {
    PROV_DISPATCH: u1 = 0,
    _1: u1 = 0,
    _2: u1 = 0,
    ALG_HANDLE_HMAC_FLAG: u1 = 0,
    _4: u1 = 0,
    HASH_REUSABLE_FLAG: u1 = 0,
    _6: u1 = 0,
    _7: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    _12: u1 = 0,
    _13: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    _16: u1 = 0,
    _17: u1 = 0,
    _18: u1 = 0,
    _19: u1 = 0,
    _20: u1 = 0,
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

const BCRYPT_AES_ALGORITHM = std.unicode.utf8ToUtf16LeStringLiteral("AES");

extern "bcrypt" fn BCryptOpenAlgorithmProvider(
    phAlgorithm: ?*BCRYPT_HANDLE,
    pszAlgId: ?[*:0]const u16,
    pszImplementation: ?[*:0]const u16,
    dwFlags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) callconv(windows.WINAPI) windows.NTSTATUS;

const BCRYPT_OBJECT_LENGTH = std.unicode.utf8ToUtf16LeStringLiteral("ObjectLength");
const BCRYPT_BLOCK_LENGTH = std.unicode.utf8ToUtf16LeStringLiteral("BlockLength");

extern "bcrypt" fn BCryptGetProperty(
    hObject: BCRYPT_HANDLE,
    pszProperty: ?[*:0]const u16,
    pbOutput: ?*u8,
    cbOutput: u32,
    pcbResult: ?*u32,
    dwFlags: u32,
) callconv(WINAPI) NTSTATUS;

const BCRYPT_CHAINING_MODE = std.unicode.utf8ToUtf16LeStringLiteral("ChainingMode");
const BCRYPT_CHAIN_MODE_CBC = std.unicode.utf8ToUtf16LeStringLiteral("ChainingModeCBC");

extern "bcrypt" fn BCryptSetProperty(
    hObject: BCRYPT_HANDLE,
    pszProperty: ?[*:0]const u16,
    pbInput: ?*u8,
    cbInput: u32,
    dwFlags: u32,
) callconv(WINAPI) NTSTATUS;

extern "bcrypt" fn BCryptGenerateSymmetricKey(
    hAlgorithm: BCRYPT_HANDLE,
    phKey: ?*BCRYPT_KEY_HANDLE,
    pbKeyObject: ?*u8,
    cbKeyObject: u32,
    pbSecret: ?*u8,
    cbSecret: u32,
    dwFlags: u32,
) callconv(WINAPI) NTSTATUS;

const NCRYPT_FLAGS = packed struct(u32) {
    BCRYPT_PAD_NONE: u1 = 0,
    BCRYPT_PAD_PKCS1: u1 = 0,
    BCRYPT_PAD_OAEP: u1 = 0,
    BCRYPT_PAD_PSS: u1 = 0,
    _4: u1 = 0,
    NCRYPT_MACHINE_KEY_FLAG: u1 = 0,
    NCRYPT_SILENT_FLAG: u1 = 0,
    NCRYPT_OVERWRITE_KEY_FLAG: u1 = 0,
    _8: u1 = 0,
    NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    _12: u1 = 0,
    _13: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    _16: u1 = 0,
    _17: u1 = 0,
    _18: u1 = 0,
    _19: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    NCRYPT_PERSIST_ONLY_FLAG: u1 = 0,
    NCRYPT_PERSIST_FLAG: u1 = 0,
};

extern "bcrypt" fn BCryptEncrypt(
    hKey: BCRYPT_KEY_HANDLE,
    pbInput: ?*u8,
    cbInput: u32,
    pPaddingInfo: ?*anyopaque,
    pbIV: ?*u8,
    cbIV: u32,
    pbOutput: ?*u8,
    cbOutput: u32,
    pcbResult: ?*u32,
    dwFlags: NCRYPT_FLAGS,
) callconv(WINAPI) NTSTATUS;

extern "bcrypt" fn BCryptDecrypt(
    hKey: BCRYPT_KEY_HANDLE,
    pbInput: ?*u8,
    cbInput: u32,
    pPaddingInfo: ?*anyopaque,
    pbIV: ?*u8,
    cbIV: u32,
    pbOutput: ?*u8,
    cbOutput: u32,
    pcbResult: ?*u32,
    dwFlags: NCRYPT_FLAGS,
) callconv(WINAPI) NTSTATUS;

extern "bcrypt" fn BCryptDestroyKey(
    hKey: BCRYPT_KEY_HANDLE,
) callconv(WINAPI) NTSTATUS;

extern "bcrypt" fn BCryptCloseAlgorithmProvider(
    hAlgorithm: BCRYPT_HANDLE,
    dwFlags: u32,
) callconv(WINAPI) NTSTATUS;

fn installAesEncryption(allocator: std.mem.Allocator, plain_text: []const u8, key: [KEYSIZE:0]u8, iv: ?[IVSIZE:0]u8) ![]u8 {
    const plain_text_size: u32 = @intCast(plain_text.len);

    var h_algorithm: BCRYPT_HANDLE = 0;
    var h_key_handle: BCRYPT_KEY_HANDLE = 0;

    // "cb" stands for "count of bytes" in Microsoft APIs
    var cb_result: u32 = 0;
    var block_size: u32 = 0;
    var cb_key_object: u32 = 0;
    var cb_cipher_text: u32 = 0;

    var status = BCryptOpenAlgorithmProvider(
        &h_algorithm,
        BCRYPT_AES_ALGORITHM,
        null,
        .{},
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptOpenAlgorithmProvider;
    }
    defer _ = BCryptCloseAlgorithmProvider(h_algorithm, 0);

    status = BCryptGetProperty(
        h_algorithm,
        BCRYPT_OBJECT_LENGTH,
        @ptrCast(&cb_key_object),
        @sizeOf(u32),
        &cb_result,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGetProperty[1] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGetPropertyFailed;
    }

    status = BCryptGetProperty(
        h_algorithm,
        BCRYPT_BLOCK_LENGTH,
        @ptrCast(&block_size),
        @sizeOf(u32),
        &cb_result,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGetProperty[2] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGetPropertyFailed;
    }

    if (block_size != 16) return error.InvalidBlockSize;

    status = BCryptSetProperty(
        h_algorithm,
        BCRYPT_CHAINING_MODE,
        @ptrCast(@constCast(BCRYPT_CHAIN_MODE_CBC)),
        BCRYPT_CHAIN_MODE_CBC.len,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptSetProperty Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptSetPropertyFailed;
    }

    // "pb" stands for "pointer to bytes" in Microsoft APIs

    const pb_key_object = try allocator.alloc(u8, cb_key_object);
    defer allocator.free(pb_key_object);

    status = BCryptGenerateSymmetricKey(
        h_algorithm,
        &h_key_handle,
        @ptrCast(pb_key_object),
        cb_key_object,
        @ptrCast(@constCast(&key)),
        KEYSIZE,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGenerateSymmetricKeyFailed;
    }
    defer _ = BCryptDestroyKey(h_key_handle);

    status = BCryptEncrypt(
        h_key_handle,
        @ptrCast(@constCast(plain_text)),
        plain_text_size,
        null,
        if (iv) |*iv_ptr| @ptrCast(@constCast(iv_ptr)) else null,
        IVSIZE,
        null,
        0,
        &cb_cipher_text,
        .{ .BCRYPT_PAD_NONE = 1 },
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptEncrypt[1] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptEncryptFailed;
    }

    const pb_cipher_text = try allocator.alloc(u8, cb_cipher_text);

    status = BCryptEncrypt(
        h_key_handle,
        @ptrCast(@constCast(plain_text)),
        plain_text_size,
        null,
        if (iv) |*iv_ptr| @ptrCast(@constCast(iv_ptr)) else null,
        IVSIZE,
        @ptrCast(pb_cipher_text),
        cb_cipher_text,
        &cb_result,
        .{ .BCRYPT_PAD_NONE = 1 },
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptEncrypt[2] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptEncryptFailed;
    }

    return pb_cipher_text;
}

fn installAesDecryption(allocator: std.mem.Allocator, cipher_text: []const u8, key: [KEYSIZE:0]u8, iv: ?[IVSIZE:0]u8) ![]u8 {
    const cipher_text_size: u32 = @intCast(cipher_text.len);

    var h_algorithm: BCRYPT_HANDLE = 0;
    var h_key_handle: BCRYPT_KEY_HANDLE = 0;

    // "cb" stands for "count of bytes" in Microsoft APIs
    var cb_result: u32 = 0;
    var block_size: u32 = 0;
    var cb_key_object: u32 = 0;
    var cb_plain_text: u32 = 0;

    var status = BCryptOpenAlgorithmProvider(
        &h_algorithm,
        BCRYPT_AES_ALGORITHM,
        null,
        .{},
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptOpenAlgorithmProvider;
    }
    defer _ = BCryptCloseAlgorithmProvider(h_algorithm, 0);

    status = BCryptGetProperty(
        h_algorithm,
        BCRYPT_OBJECT_LENGTH,
        @ptrCast(&cb_key_object),
        @sizeOf(u32),
        &cb_result,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGetProperty[1] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGetPropertyFailed;
    }

    status = BCryptGetProperty(
        h_algorithm,
        BCRYPT_BLOCK_LENGTH,
        @ptrCast(&block_size),
        @sizeOf(u32),
        &cb_result,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGetProperty[2] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGetPropertyFailed;
    }

    if (block_size != 16) return error.InvalidBlockSize;

    status = BCryptSetProperty(
        h_algorithm,
        BCRYPT_CHAINING_MODE,
        @ptrCast(@constCast(BCRYPT_CHAIN_MODE_CBC)),
        BCRYPT_CHAIN_MODE_CBC.len,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptSetProperty Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptSetPropertyFailed;
    }

    // "pb" stands for "pointer to bytes" in Microsoft APIs

    const pb_key_object = try allocator.alloc(u8, cb_key_object);
    defer allocator.free(pb_key_object);

    status = BCryptGenerateSymmetricKey(
        h_algorithm,
        &h_key_handle,
        @ptrCast(pb_key_object),
        cb_key_object,
        @ptrCast(@constCast(&key)),
        KEYSIZE,
        0,
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptGenerateSymmetricKeyFailed;
    }
    defer _ = BCryptDestroyKey(h_key_handle);

    status = BCryptDecrypt(
        h_key_handle,
        @ptrCast(@constCast(cipher_text)),
        cipher_text_size,
        null,
        if (iv) |*iv_ptr| @ptrCast(@constCast(iv_ptr)) else null,
        IVSIZE,
        null,
        0,
        &cb_plain_text,
        .{ .BCRYPT_PAD_NONE = 1 },
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptDecrypt[1] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptDecryptFailed;
    }

    const pb_plain_text = try allocator.alloc(u8, cb_plain_text);

    status = BCryptDecrypt(
        h_key_handle,
        @ptrCast(@constCast(cipher_text)),
        cipher_text_size,
        null,
        if (iv) |*iv_ptr| @ptrCast(@constCast(iv_ptr)) else null,
        IVSIZE,
        @ptrCast(pb_plain_text),
        cb_plain_text,
        &cb_result,
        .{ .BCRYPT_PAD_NONE = 1 },
    );
    if (status != .SUCCESS) {
        std.debug.print("[!] BCryptDecrypt[2] Failed With Error: {s}\n", .{@tagName(status)});
        return error.BCryptDecryptFailed;
    }

    return pb_plain_text;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const rand = std.crypto.random;

    const text = "Hello, World!";

    var key: [KEYSIZE:0]u8 = undefined;
    rand.bytes(&key);

    var iv: [IVSIZE:0]u8 = undefined;
    rand.bytes(&iv);

    const cipher_text = try installAesEncryption(
        allocator,
        text,
        key,
        iv,
    );
    defer allocator.free(cipher_text);

    const decrypted_text = try installAesDecryption(
        allocator,
        cipher_text,
        key,
        iv,
    );
    defer allocator.free(decrypted_text);

    std.debug.print("[+] text: {x}\n", .{text});
    std.debug.print("[+] cipher_text: {x}\n", .{cipher_text});
    std.debug.print("[+] decrypted_text: {x}\n", .{decrypted_text});
}
