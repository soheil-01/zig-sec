const std = @import("std");
const win = @import("zigwin32").everything;

const NTSTATUS = win.NTSTATUS;
const WINAPI = win.WINAPI;
const LPSTR = win.LPSTR;

const KEYSIZE: u32 = 32;
const IVSIZE: u32 = 16;

const BCRYPT_HANDLE = win.BCRYPT_HANDLE;
const BCRYPT_KEY_HANDLE = win.BCRYPT_KEY_HANDLE;

const BCRYPT_AES_ALGORITHM = std.unicode.utf8ToUtf16LeStringLiteral("AES");
const BCRYPT_OBJECT_LENGTH = std.unicode.utf8ToUtf16LeStringLiteral("ObjectLength");
const BCRYPT_BLOCK_LENGTH = std.unicode.utf8ToUtf16LeStringLiteral("BlockLength");
const BCRYPT_CHAINING_MODE = std.unicode.utf8ToUtf16LeStringLiteral("ChainingMode");
const BCRYPT_CHAIN_MODE_CBC = std.unicode.utf8ToUtf16LeStringLiteral("ChainingModeCBC");

const BCryptOpenAlgorithmProvider = win.BCryptOpenAlgorithmProvider;
const BCryptGetProperty = win.BCryptGetProperty;
const BCryptSetProperty = win.BCryptSetProperty;
const BCryptGenerateSymmetricKey = win.BCryptGenerateSymmetricKey;
const BCryptEncrypt = win.BCryptEncrypt;
const BCryptDecrypt = win.BCryptDecrypt;
const BCryptDestroyKey = win.BCryptDestroyKey;
const BCryptCloseAlgorithmProvider = win.BCryptCloseAlgorithmProvider;

pub fn installAesEncryption(allocator: std.mem.Allocator, plain_text: []const u8, key: [KEYSIZE:0]u8, iv: ?[IVSIZE:0]u8) ![]u8 {
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
    if (status != 0) {
        std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGetProperty[1] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGetProperty[2] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptSetProperty Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptEncrypt[1] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptEncrypt[2] Failed With Error Code: {d}\n", .{status});
        return error.BCryptEncryptFailed;
    }

    return pb_cipher_text;
}

pub fn installAesDecryption(allocator: std.mem.Allocator, cipher_text: []const u8, key: [KEYSIZE:0]u8, iv: ?[IVSIZE:0]u8) ![]u8 {
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
    if (status != 0) {
        std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGetProperty[1] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGetProperty[2] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptSetProperty Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptDecrypt[1] Failed With Error Code: {d}\n", .{status});
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
    if (status != 0) {
        std.debug.print("[!] BCryptDecrypt[2] Failed With Error Code: {d}\n", .{status});
        return error.BCryptDecryptFailed;
    }

    return pb_plain_text;
}
