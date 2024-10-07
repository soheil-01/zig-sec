const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    const string = "Maldev";

    std.debug.print("[+] Djb2 Hash of \"{s}\": 0x{X}\n", .{ string, sec.hash.djb2(string) });
    std.debug.print("[+] JenkinsOneAtATime32 Hash of \"{s}\": 0x{X}\n", .{ string, sec.hash.jenkinsOneAtATime32(string) });
    std.debug.print("[+] LoseLose Hash of \"{s}\": 0x{X}\n", .{ string, sec.hash.loseLose(string) });
    std.debug.print("[+] Rotr32 Hash of \"{s}\": 0x{X}\n", .{ string, sec.hash.rotr32(string) });
}
