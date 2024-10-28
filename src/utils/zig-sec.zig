pub const payload_obfuscation = struct {
    pub const ipv4 = @import("payload_obfuscation/ipv4.zig");
    pub const ipv6 = @import("payload_obfuscation/ipv6.zig");
    pub const mac = @import("payload_obfuscation/mac.zig");
    pub const uuid = @import("payload_obfuscation/uuid.zig");
};

pub const payload_encryption = struct {
    pub const xor = @import("payload_encryption/xor.zig");
    pub const rc4 = @import("payload_encryption/rc4.zig");
    pub const bcrypt_aes = @import("payload_encryption/bcrypt_aes.zig");
};

pub const payload_staging = struct {
    pub const web_server = @import("payload_staging/web_server.zig");
    pub const windows_registry = @import("payload_staging/windows_registry.zig");
};

pub const code_injection = struct {
    pub const local = @import("code_injection/local.zig");
    pub const remote = @import("code_injection/remote.zig");
};

pub const hook = struct {
    pub const minhook = @import("hook/minhook.zig");
    pub const custom = @import("hook/custom.zig");
    pub const detours = @import("hook/detours.zig");
};

pub const process = @import("process.zig");
pub const thread = @import("thread.zig");
pub const common = @import("common.zig");
pub const hash = @import("hash.zig");
pub const win = @import("win.zig");
pub const syscall = @import("syscall.zig");
pub const anti_debugging = @import("anti_debugging.zig");
