const std = @import("std");
const win = @import("zigwin32").everything;
const sec = @import("zig-sec");

const GetModuleHandleA = win.GetModuleHandleA;
const GetProcAddress = win.GetProcAddress;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;

// calculating the hash at compile time
const ntallocatevirtualmemory_hash = sec.hash.jenkinsOneAtATime32("NtAllocateVirtualMemory");

pub fn main() !void {
    const h_module = GetModuleHandleA("ntdll.dll") orelse {
        std.debug.print("[!] GetModuleHandleA Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.GetModuleHandleAFailed;
    };
    defer _ = CloseHandle(h_module);

    const nt_allocate_virtual_memory_1 = GetProcAddress(h_module, "NtAllocateVirtualMemory") orelse return;
    const nt_allocate_virtual_memory_2 = try sec.win.getProcAddressReplacement(h_module, "NtAllocateVirtualMemory") orelse return;
    const nt_allocate_virtual_memory_3 = try sec.win.getProcAddressH(h_module, ntallocatevirtualmemory_hash);

    std.debug.print("[+] NtAllocateVirtualMemory 1: 0x{X}\n", .{@intFromPtr(nt_allocate_virtual_memory_1)});
    std.debug.print("[+] NtAllocateVirtualMemory 2: 0x{X}\n", .{@intFromPtr(nt_allocate_virtual_memory_2)});
    std.debug.print("[+] NtAllocateVirtualMemory 3: 0x{X}\n", .{@intFromPtr(nt_allocate_virtual_memory_3)});
}
