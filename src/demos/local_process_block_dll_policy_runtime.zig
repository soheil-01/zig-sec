const std = @import("std");
const win = @import("zigwin32").everything;

const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = win.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;

const SetProcessMitigationPolicy = win.SetProcessMitigationPolicy;
const GetLastError = win.GetLastError;

const SLEEP_TIME = std.time.ns_per_s * 10;

pub fn main() !void {
    var policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY{ .Anonymous = .{ .Flags = 1 } };

    std.debug.print("[!] Check Mitigation Policies\n", .{});
    std.time.sleep(SLEEP_TIME);

    if (SetProcessMitigationPolicy(.ProcessSignaturePolicy, &policy, @sizeOf(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)) == 0) {
        std.debug.print("[!] SetProcessMitigationPolicy Failed With Error: {s}\n", .{@tagName(GetLastError())});
        return error.SetProcessMitigationPolicyFailed;
    }

    std.debug.print("[!]Check Mitigation Policies Agian\n", .{});
    std.time.sleep(SLEEP_TIME);
}
