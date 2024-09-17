const std = @import("std");
const payload_obfuscation = @import("zig-sec").payload_obfuscation;

pub fn main() !void {
    const writer = std.io.getStdOut().writer();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingPayloadPath;
    if (args.len < 3) return error.MissingObfuscationMode;

    const payload_path = args[1];
    const obfuscation_mode = args[2];

    const payload = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(u32));
    defer allocator.free(payload);

    if (std.mem.eql(u8, obfuscation_mode, "ipv4")) {
        const ipv4_array = try payload_obfuscation.ipv4.obfuscate(allocator, payload);
        defer payload_obfuscation.ipv4.freeIpv4Array(allocator, ipv4_array);
        try payload_obfuscation.ipv4.printIpv4Array(writer, ipv4_array);
    } else if (std.mem.eql(u8, obfuscation_mode, "ipv6")) {
        const ipv6_array = try payload_obfuscation.ipv6.obfuscate(allocator, payload);
        defer payload_obfuscation.ipv6.freeIpv6Array(allocator, ipv6_array);
        try payload_obfuscation.ipv6.printIpv6Array(writer, ipv6_array);
    } else if (std.mem.eql(u8, obfuscation_mode, "mac")) {
        const mac_array = try payload_obfuscation.mac.obfuscate(allocator, payload);
        defer payload_obfuscation.mac.freeMacArray(allocator, mac_array);
        try payload_obfuscation.mac.printMacArray(writer, mac_array);
    } else if (std.mem.eql(u8, obfuscation_mode, "uuid")) {
        const uuid_array = try payload_obfuscation.uuid.obfuscate(allocator, payload);
        defer payload_obfuscation.uuid.freeUUidArray(allocator, uuid_array);
        try payload_obfuscation.uuid.printUUidArray(writer, uuid_array);
    } else return error.InvalidObfuscationMode;
}
