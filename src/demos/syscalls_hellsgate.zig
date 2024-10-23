const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;

const HANDLE = win.HANDLE;

fn syscall2(ssn: u32, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\movq %rcx, %r10
        \\movl %[ssn], %eax
        \\syscall
        : [ret] "={rax}" (-> usize),
        : [ssn] "rm" (ssn),
          [arg1] "{rcx}" (arg1),
          [arg2] "{rdx}" (arg2),
        : "r10", "r11"
    );
}

fn NtTerminateProcess(allocator: std.mem.Allocator, process_handle: usize, exit_status: usize) !usize {
    const ssn = try sec.syscall.getSyscallNumberHellsGate(allocator, "NtTerminateProcess");
    return syscall2(ssn, process_handle, exit_status);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const process = try sec.process.openProcessByName("notepad.exe");

    _ = try NtTerminateProcess(allocator, @intFromPtr(process.h_process), 0);
}
