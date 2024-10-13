const std = @import("std");
const path = std.fs.path;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const is_windows = target.query.os_tag == .windows;

    const tiny_aes_lib = b.addStaticLibrary(.{
        .name = "aes",
        .optimize = .Debug,
        .target = target,
    });
    tiny_aes_lib.addCSourceFiles(.{
        .files = &.{"lib/aes/aes.c"},
        .flags = &.{"-std=c99"},
    });
    tiny_aes_lib.linkLibC();

    const seg_access_lib = b.addStaticLibrary(.{
        .name = "seg_access",
        .optimize = .Debug,
        .target = target,
    });
    seg_access_lib.addCSourceFiles(.{
        .files = &.{"lib/seg_access/seg_access.c"},
        .flags = &.{"-std=c99"},
    });
    seg_access_lib.linkLibC();

    const zigwin32_module = b.dependency("zigwin32", .{}).module("zigwin32");

    const module = b.addModule("zig-sec", .{
        .root_source_file = b.path("src/utils/zig-sec.zig"),
        .imports = &.{
            .{ .name = "zigwin32", .module = zigwin32_module },
        },
        .link_libc = is_windows,
    });
    if (is_windows) {
        module.addIncludePath(b.path("lib"));
        module.linkLibrary(seg_access_lib);
    }

    const file_to_build = b.option(
        []const u8,
        "file",
        "Specify the file to build",
    ) orelse "src/main.zig";

    const build_type = b.option(
        enum { exe, lib },
        "type",
        "Specify build type: exe or lib",
    ) orelse .exe;

    const use_aes_lib = b.option(
        bool,
        "use-aes",
        "Include Tiny-AES library in the build",
    ) orelse false;

    switch (build_type) {
        .exe => {
            const exe = b.addExecutable(.{
                .name = path.stem(file_to_build),
                .root_source_file = b.path(file_to_build),
                .target = target,
                .optimize = optimize,
            });
            exe.root_module.addImport("zigwin32", zigwin32_module);
            exe.root_module.addImport("zig-sec", module);
            exe.addIncludePath(b.path("lib"));

            if (is_windows) {
                exe.linkLibrary(seg_access_lib);
                exe.linkLibC();

                if (use_aes_lib) {
                    exe.linkLibrary(tiny_aes_lib);
                }
            }

            b.installArtifact(exe);

            const run_cmd = b.addRunArtifact(exe);

            run_cmd.step.dependOn(b.getInstallStep());

            if (b.args) |args| {
                run_cmd.addArgs(args);
            }

            const run_step = b.step("run", "Run the app");
            run_step.dependOn(&run_cmd.step);
        },
        .lib => {
            const lib = b.addSharedLibrary(.{
                .name = std.fs.path.stem(file_to_build),
                .root_source_file = b.path(file_to_build),
                .target = target,
                .optimize = optimize,
            });
            lib.root_module.addImport("zigwin32", zigwin32_module);
            lib.addIncludePath(b.path("lib"));

            if (is_windows) {
                lib.linkLibrary(seg_access_lib);
                lib.linkLibC();

                if (use_aes_lib) {
                    lib.linkLibrary(tiny_aes_lib);
                }
            }

            b.installArtifact(lib);
        },
    }
}
