pub fn xorByOneKey(shell_code: []u8, key: u8) void {
    for (0..shell_code.len) |i| shell_code[i] = shell_code[i] ^ key;
}

pub fn xorByiKeys(shell_code: []u8, key: u8) void {
    for (0..shell_code.len) |i| shell_code[i] = shell_code[i] ^ (key +% @as(u8, @intCast(i % 256)));
}

pub fn xorByInputKey(shell_code: []u8, key: []const u8) void {
    for (0..shell_code.len) |i| shell_code[i] = shell_code[i] ^ key[i % key.len];
}
