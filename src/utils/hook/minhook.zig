const std = @import("std");
const builtin = @import("builtin");

const win = std.os.windows;

const minhook = switch (builtin.cpu.arch) {
    .x86 => struct {
        extern "minhook/MinHook.x86" fn MH_Initialize() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_Uninitialize() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_ApplyQueued() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_QueueEnableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_QueueDisableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_RemoveHook(*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_EnableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_DisableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_CreateHook(*align(1) const anyopaque, *align(1) const anyopaque, ?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x86" fn MH_CreateHookApi(win.LPCWSTR, win.LPCSTR, *align(1) const anyopaque, ?*align(1) const anyopaque) callconv(.C) MH_STATUS;
    },
    .x86_64 => struct {
        extern "minhook/MinHook.x64" fn MH_Initialize() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_Uninitialize() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_ApplyQueued() callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_QueueEnableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_QueueDisableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_RemoveHook(*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_EnableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_DisableHook(?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_CreateHook(*align(1) const anyopaque, *align(1) const anyopaque, ?*align(1) const anyopaque) callconv(.C) MH_STATUS;
        extern "minhook/MinHook.x64" fn MH_CreateHookApi(win.LPCWSTR, win.LPCSTR, *align(1) const anyopaque, ?*align(1) const anyopaque) callconv(.C) MH_STATUS;
    },
    else => unreachable,
};

const MH_STATUS = enum(c_int) {
    MH_UNKNOWN = -1,
    MH_OK,
    MH_ERROR_ALREADY_INITIALIZED,
    MH_ERROR_NOT_INITIALIZED,
    MH_ERROR_ALREADY_CREATED,
    MH_ERROR_NOT_CREATED,
    MH_ERROR_ENABLED,
    MH_ERROR_DISABLED,
    MH_ERROR_NOT_EXECUTABLE,
    MH_ERROR_UNSUPPORTED_FUNCTION,
    MH_ERROR_MEMORY_ALLOC,
    MH_ERROR_MEMORY_PROTECT,
    MH_ERROR_MODULE_NOT_FOUND,
    MH_ERROR_FUNCTION_NOT_FOUND,
};

pub const MH_ALL_HOOKS = null;

/// Initialize the MinHook library. You must call this function EXACTLY ONCE at the beginning of your program.
pub fn initialize() MH_STATUS {
    return minhook.MH_Initialize();
}

/// Uninitialize the MinHook library. You must call this function EXACTLY ONCE at the end of your program.
pub fn uninitialize() MH_STATUS {
    return minhook.MH_Uninitialize();
}

/// Creates a Hook for the specified target function, in disabled state.
///
/// Parameters:
/// - target [in]: A pointer to the target function, which will be overridden by the detour function.
/// - detour [in]:  A pointer to the detour function, which will override the target function.
/// - original [out]: A pointer to the trampoline function, which will be used to call the original target function. Can be `null`.
pub fn createHook(target: *const anyopaque, detour: *const anyopaque, original: ?*const anyopaque) MH_STATUS {
    return minhook.MH_CreateHook(target, detour, original);
}

// Creates a hook for the specified API function, in disabled state.
///
// Parameters:
// - module [in]: A pointer to the loaded module name which contains the target function.
// - proc_name [in]: A pointer to the target function name, which will be overridden by the detour function.
// - detour [in]:  A pointer to the detour function, which will override the target function.
// - original [out]: A pointer to the trampoline function, which will be used to call the original target function This parameter can be NULL.
pub fn createHookApi(module: win.LPCWSTR, proc_name: win.LPCSTR, detour: *const anyopaque, original: ?*const anyopaque) MH_STATUS {
    return minhook.MH_CreateHookApi(module, proc_name, detour, original);
}

/// Enables an already created hook.
///
/// Parameters:
/// - target [in]: A pointer to the target function. If this parameter is `MH_ALL_HOOKS`, all created hooks are enabled in one go.
pub fn enableHook(target: ?*const anyopaque) MH_STATUS {
    return minhook.MH_EnableHook(target);
}

/// Disables an already created hook.
///
/// Parameters:
/// - target [in]: A pointer to the target function. If this parameter is `MH_ALL_HOOKS`, all created hooks are disabled in one go.
pub fn disableHook(target: ?*const anyopaque) MH_STATUS {
    return minhook.MH_DisableHook(target);
}

/// Removes an already created hook.
///
/// Parameters:
/// - target [in]: A pointer to the target function.
pub fn removeHook(target: *const anyopaque) MH_STATUS {
    return minhook.MH_RemoveHook(target);
}

/// Applies all queued changes in one go.
pub fn applyQueued() MH_STATUS {
    return minhook.MH_ApplyQueued();
}

/// Queues to disable an already created hook.
///
/// Parameters:
/// - target [in]: A pointer to the target function. If this parameter is `MH_ALL_HOOKS`, all created hooks are queued to be disabled.
pub fn queueEnableHook(target: ?*const anyopaque) MH_STATUS {
    return minhook.MH_QueueEnableHook(target);
}

/// Queues to disable an already created hook.
///
/// Parameters:
/// - target [in] A pointer to the target function. If this parameter is `MH_ALL_HOOKS`, all created hooks are queued to be disabled.
pub fn queueDisableHook(target: ?*const anyopaque) MH_STATUS {
    return minhook.MH_DisableHook(target);
}
