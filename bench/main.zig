//! Single-process file benchmark driver. Timings are collected externally.
const std = @import("std");
const Bough = @import("bough");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) return error.ExpectedModeAndInputPath;
    if (std.mem.eql(u8, args[1], "verify")) {
        return verify(init, args);
    }
    const root = if (std.mem.eql(u8, args[1], "hash"))
        try Bough.hashFile(init.io, .cwd(), args[2])
    else if (std.mem.eql(u8, args[1], "parallel")) blk: {
        if (args.len != 5) return error.ExpectedOutputPathAndWorkers;
        if (std.mem.eql(u8, args[2], args[3])) return error.InputIsOutput;
        const workers = try std.fmt.parseInt(usize, args[4], 10);
        const input = try std.Io.Dir.cwd().openFile(init.io, args[2], .{});
        defer input.close(init.io);
        const stat = try input.stat(init.io);
        const output = try std.Io.Dir.cwd().createFile(init.io, args[3], .{});
        defer output.close(init.io);
        break :blk try Bough.Parallel.encodeFile(init.io, init.gpa, input, stat.size, output, workers);
    } else if (std.mem.eql(u8, args[1], "outboard")) blk: {
        if (args.len != 4) return error.ExpectedOutputPath;
        if (std.mem.eql(u8, args[2], args[3])) return error.InputIsOutput;
        const file = try std.Io.Dir.cwd().createFile(init.io, args[3], .{});
        defer file.close(init.io);
        var buffer: [1024 * 1024]u8 = undefined;
        var writer = file.writerStreaming(init.io, &buffer);
        const encoded = try Bough.encodeFile(init.io, .cwd(), args[2], &writer.interface);
        try writer.interface.flush();
        break :blk encoded.root;
    } else return error.UnknownMode;
    std.debug.print("{x}\n", .{root});
}

/// Resident input, file-backed proofs, discarded output. Preparation and input
/// loading are outside the timed region; proof reads and output copies are in it.
fn verify(init: std.process.Init, args: []const [:0]const u8) !void {
    if (args.len != 6) return error.ExpectedInputOutboardRootAndRepeats;
    const content = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], init.gpa, .unlimited);
    defer init.gpa.free(content);
    var ob = try Bough.OutboardReader.open(init.io, .cwd(), args[3]);
    defer ob.close();
    if (content.len != ob.content_length) return error.WrongLength;
    var root: Bough.Hash = undefined;
    if ((try std.fmt.hexToBytes(&root, args[4])).len != root.len) return error.WrongRootLength;
    const repeats = try std.fmt.parseInt(usize, args[5], 10);
    if (repeats == 0) return error.ZeroRepeats;
    const verifier = try init.gpa.create(Bough.Verifier);
    defer init.gpa.destroy(verifier);
    var dest: [65536]u8 = undefined;
    var first_ns: i96 = 0;
    const start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (0..repeats) |iteration| {
        var reader = std.Io.Reader.fixed(content);
        verifier.* = Bough.Verifier.init(init.io, &ob, &reader, root);
        var count: usize = 0;
        while (true) {
            const n = try verifier.read(&dest);
            if (iteration == 0 and count == 0) {
                first_ns = std.Io.Clock.awake.now(init.io).nanoseconds - start;
            }
            if (n == 0) break;
            count += n;
        }
        if (count != content.len) return error.WrongLength;
    }
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
    std.debug.print(
        "{{\"bytes\":{d},\"elapsed_ns\":{d},\"first_read_ns\":{d},\"verifier_bytes\":{d}}}\n",
        .{ content.len * repeats, elapsed, first_ns, @sizeOf(Bough.Verifier) },
    );
}
