const builtin = @import("builtin");

const detours = switch (builtin.cpu.arch) {
    .x86_64 => struct {
        pub extern "detours/detours.x64" fn DetourUpdateThread(handle: ?*const anyopaque) c_long;

        pub extern "detours/detours.x64" fn DetourAttach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) c_long;
        pub extern "detours/detours.x64" fn DetourDetach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) c_long;

        pub extern "detours/detours.x64" fn DetourTransactionBegin() c_long;
        pub extern "detours/detours.x64" fn DetourTransactionAbort() c_long;
        pub extern "detours/detours.x64" fn DetourTransactionCommit() c_long;

        pub extern "detours/detours.x64" fn DetourRestoreAfterWith() c_int;
    },
    .x86 => struct {
        pub extern "detours/detours.x86" fn DetourUpdateThread(handle: ?*const anyopaque) callconv(.Stdcall) c_long;

        pub extern "detours/detours.x86" fn DetourAttach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) callconv(.Stdcall) c_long;
        pub extern "detours/detours.x86" fn DetourDetach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) callconv(.Stdcall) c_long;

        pub extern "detours/detours.x86" fn DetourTransactionBegin() callconv(.Stdcall) c_long;
        pub extern "detours/detours.x86" fn DetourTransactionAbort() callconv(.Stdcall) c_long;
        pub extern "detours/detours.x86" fn DetourTransactionCommit() callconv(.Stdcall) c_long;

        pub extern "detours/detours.x86" fn DetourRestoreAfterWith() callconv(.Stdcall) c_int;
    },
    else => @compileError("Unsupported CPU architecture!"),
};

/// Updates the detours in the current thread.
pub fn detourUpdateThread(thread_handle: *const anyopaque) c_long {
    return detours.DetourUpdateThread(thread_handle);
}

/// Attachs hook to target function.
/// Redirects code flow to detour function.
pub fn detourAttach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) c_long {
    return detours.DetourAttach(target_function_pointer, detour_function_pointer);
}

/// Detachs hook to from function.
/// Remove code flow redirects from detour function.
pub fn detourDetach(target_function_pointer: *const anyopaque, detour_function_pointer: *const anyopaque) c_long {
    return detours.DetourDetach(target_function_pointer, detour_function_pointer);
}

/// Begins detours transaction.
pub fn detourTransactionBegin() c_long {
    return detours.DetourTransactionBegin();
}

/// Rollbacks detours transaction.
pub fn detourTransactionAbort() c_long {
    return detours.DetourTransactionAbort();
}

/// Commits detours transaction.
pub fn detourTransactionCommit() c_long {
    return detours.DetourTransactionCommit();
}

/// Restores the contents in memory import table after a process was started.
pub fn detourRestoreAfterWith() c_int {
    return detours.DetourRestoreAfterWith();
}
