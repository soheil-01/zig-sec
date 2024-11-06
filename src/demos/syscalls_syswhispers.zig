const std = @import("std");
const sec = @import("zig-sec");

const win = std.os.windows;

const HANDLE = win.HANDLE;
const NTSTATUS = win.NTSTATUS;

// #1
// comptime {
//     asm (
//         \\.global NtTerminateProcess
//         \\.section .text
//         \\NtTerminateProcess:
//         \\  movq %rcx, %r10
//         \\  movl $0x2c, %eax
//         \\  syscall
//         \\  ret
//     );
// }

// #2
// comptime {
//     asm (
//         \\.intel_syntax noprefix
//         \\.text
//         \\.global NtTerminateProcess
//         \\NtTerminateProcess:
//         \\  mov r10, rcx
//         \\  mov eax, 0x2c
//         \\  syscall
//         \\  ret
//     );
// }

// extern fn NtTerminateProcess(process_handle: HANDLE, exit_status: NTSTATUS) callconv(win.WINAPI) NTSTATUS;

fn NtTerminateProcess(allocator: std.mem.Allocator, process_handle: HANDLE, exit_status: NTSTATUS) !NTSTATUS {
    const ssn = try sec.syscall.getSyscallNumberSysWhispers(allocator, "NtTerminateProcess");

    return @enumFromInt(sec.syscall.syscall2(
        ssn,
        @intFromPtr(process_handle),
        @intFromEnum(exit_status),
    ));
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingProcessName;

    const process_name = args[1];
    const process = try sec.process.openProcessByName(process_name);

    _ = try NtTerminateProcess(allocator, process.h_process, .SUCCESS);
}
