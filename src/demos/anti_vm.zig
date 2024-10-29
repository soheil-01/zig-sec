const std = @import("std");
const sec = @import("zig-sec");

pub fn main() !void {
    std.debug.print("[!] isVenvByHardwareCheck: {}\n", .{try sec.anti_vm.isVenvByHardwareCheck()});
    std.debug.print("[!] checkMachineResolution: {}\n", .{try sec.anti_vm.checkMachineResolution()});
    std.debug.print("[!] exeDigitsInNameCheck: {}\n", .{try sec.anti_vm.exeDigitsInNameCheck()});
    std.debug.print("[!] checkMachineProcesses: {}\n", .{try sec.anti_vm.checkMachineProcesses()});
}
