//! Bounded, positional file encoder for Bough's post-order outboard format.
//! Input must remain unchanged for the entire call. `input` and `output` must
//! refer to distinct regular files; non-regular files are rejected (the std
//! file reader/writer can otherwise fall back to shared streaming offsets).
//! Output must be writable and is resized to the exact outboard length. On
//! error the output is incomplete, not valid.
const std = @import("std");
const Bough = @import("Bough.zig");
const Allocator = std.mem.Allocator;

pub const max_workers = 16;
const worker_stack_size = 16 * 1024 * 1024;

const Work = struct {
    io: std.Io,
    input: std.Io.File,
    output: std.Io.File,
    content_length: u64,
    split: Bough.Split,
    roots: [][8]u32,
    next: std.atomic.Value(usize) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),
    errors: [max_workers]?anyerror = @splat(null),
};

fn encodeSegment(work: *Work, k: usize) !void {
    const seg = work.split.segment(@intCast(k));
    // File.Reader/Writer keep their own logical offsets. Preflight positional
    // access before spawning, and use the simple modes to avoid sendfile and
    // ensure reads/writes go through pread/pwrite, never a shared seek offset.
    var read_buf: [Bough.READ_BUF_SIZE]u8 align(8) = undefined;
    var reader = work.input.reader(work.io, &read_buf);
    reader.mode = .positional_simple;
    try reader.seekTo(seg.byteStart());

    var write_buf: [4096]u8 = undefined;
    var writer = work.output.writer(work.io, &write_buf);
    writer.mode = .positional_simple;
    try writer.seekToUnbuffered(work.split.segmentOutboardOffset(@intCast(k)));

    const root = try Bough.encodeSubtree(
        &reader.interface,
        seg.startCounter(),
        seg.byteLen(work.content_length),
        work.split.count() == 1,
        &writer.interface,
    );
    try writer.flush();
    // Disjoint segments are published in disjoint slots. A failed worker
    // leaves its slot unused; the combiner runs only after every join succeeds.
    work.roots[k] = root;
}

fn runWorker(work: *Work, slot: usize) void {
    while (!work.failed.load(.monotonic)) {
        const k = work.next.fetchAdd(1, .monotonic);
        if (k >= work.roots.len) return;
        encodeSegment(work, k) catch |err| {
            work.errors[slot] = err;
            work.failed.store(true, .monotonic);
            return;
        };
    }
}

/// Encode exactly `content_length` bytes from a stable regular input file.
/// `output` must be a separate writable regular file (not an alias of input).
/// Non-regular files return `error.NotRegularFile`; both files are checked for
/// positional access before workers start. Output is resized to the exact
/// sidecar length. No partial result is returned if a worker, thread spawn,
/// or final combine fails.
/// At most 16 worker threads and fewer than 2*workers segment roots are held.
pub fn encodeFile(
    io: std.Io,
    allocator: Allocator,
    input: std.Io.File,
    content_length: u64,
    output: std.Io.File,
    workers: usize,
) !Bough.Hash {
    if (workers == 0 or workers > max_workers) return error.InvalidWorkerCount;
    const n_chunks = if (content_length == 0) 0 else (content_length - 1) / Bough.chunk_length + 1;
    return encodeWithSplit(io, allocator, input, content_length, output, workers, Bough.subtreeSplit(n_chunks, @intCast(workers)));
}

// An explicit split lets small-file tests exercise several real threads
// without allocating 256+ chunks per segment in every test case.
fn encodeWithSplit(
    io: std.Io,
    allocator: Allocator,
    input: std.Io.File,
    content_length: u64,
    output: std.Io.File,
    workers: usize,
    split: Bough.Split,
) !Bough.Hash {
    if (workers == 0 or workers > max_workers) return error.InvalidWorkerCount;
    // File.Reader/Writer silently switch to streaming on Unseekable. Never
    // give them a pipe/device/socket, even for empty content (no worker).
    if ((try input.stat(io)).kind != .file or (try output.stat(io)).kind != .file)
        return error.NotRegularFile;
    // Check positional reads on every call, including an empty input. The
    // header write below checks positional output before any worker starts.
    var probe: [1]u8 = undefined;
    if (try input.readPositionalAll(io, &probe, 0) != 1 and content_length > 0)
        return error.UnexpectedEof;

    const count: usize = @intCast(split.count());
    const roots = try allocator.alloc([8]u32, count);
    defer allocator.free(roots);
    const n_internal = if (split.total_chunks <= 1) 0 else split.total_chunks - 2;
    const expected_size: u64 = 8 + 32 * n_internal;
    try output.setLength(io, expected_size);
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u64, &hdr, content_length, .little);
    try output.writePositionalAll(io, &hdr, 0);

    var work: Work = .{
        .io = io,
        .input = input,
        .output = output,
        .content_length = content_length,
        .split = split,
        .roots = roots,
    };
    var threads: [max_workers]std.Thread = undefined;
    var spawned: usize = 0;
    const lanes = @min(workers, count);
    while (spawned < lanes) {
        threads[spawned] = std.Thread.spawn(.{ .stack_size = worker_stack_size }, runWorker, .{ &work, spawned }) catch |err| {
            work.failed.store(true, .monotonic);
            for (threads[0..spawned]) |thread| thread.join();
            return err;
        };
        spawned += 1;
    }
    for (threads[0..spawned]) |thread| thread.join();
    for (work.errors[0..spawned]) |err| if (err) |e| return e;

    return Bough.combineSubtreesPositional(split, content_length, roots, io, output);
}

const testing = std.testing;

fn compareToSequential(io: std.Io, tmp: std.Io.Dir, content: []const u8, workers: usize, seg_chunks: u64) !void {
    var input = try tmp.createFile(io, "input.bin", .{ .read = true });
    defer input.close(io);
    try input.writePositionalAll(io, content, 0);
    var output = try tmp.createFile(io, "out.bao", .{ .read = true });
    defer output.close(io);
    try output.setLength(io, 1_000); // ensure old trailing bytes are removed

    const n_chunks: u64 = if (content.len == 0) 0 else (content.len - 1) / Bough.chunk_length + 1;
    const split = Bough.Split{ .seg_chunks = if (n_chunks == 0) 0 else seg_chunks, .total_chunks = n_chunks };
    if (n_chunks > seg_chunks and workers > 1) try testing.expect(split.count() > 1);
    const got = try encodeWithSplit(io, testing.allocator, input, content.len, output, workers, split);

    const out_len: usize = 8 + 32 * @as(usize, @intCast(if (n_chunks <= 1) 0 else n_chunks - 2));
    const reference = try testing.allocator.alloc(u8, out_len);
    defer testing.allocator.free(reference);
    var ref_reader: std.Io.Reader = .fixed(content);
    var ref_writer: std.Io.Writer = .fixed(reference);
    const expected = try Bough.encodeReader(&ref_reader, content.len, &ref_writer);
    try testing.expectEqualSlices(u8, &expected.root, &got);
    try testing.expectEqual(out_len, ref_writer.end);
    try testing.expectEqual(@as(u64, @intCast(out_len)), (try output.stat(io)).size);
    const actual = try testing.allocator.alloc(u8, out_len);
    defer testing.allocator.free(actual);
    try testing.expectEqual(out_len, try output.readPositionalAll(io, actual, 0));
    try testing.expectEqualSlices(u8, reference, actual);
}

test "positional workers produce exactly sequential outboard and root" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const chunk = Bough.chunk_length;
    const sizes = [_]usize{ 0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 3 * chunk, 4 * chunk, 5 * chunk + 73, 9 * chunk + 127 };
    for (sizes) |size| {
        const bytes = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(bytes);
        for (bytes, 0..) |*byte, i| byte.* = @truncate(i *% 137 +% size);
        try compareToSequential(io, tmp.dir, bytes, 4, 1);
        try compareToSequential(io, tmp.dir, bytes, 3, 2);
        try compareToSequential(io, tmp.dir, bytes, 2, 4);
    }
}

test "production split boundaries, invalid workers, and truncated input" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var input = try tmp.dir.createFile(io, "in", .{ .read = true });
    defer input.close(io);
    var output = try tmp.dir.createFile(io, "out", .{ .read = true });
    defer output.close(io);
    try testing.expectError(error.InvalidWorkerCount, encodeFile(io, testing.allocator, input, 0, output, 0));
    try testing.expectError(error.InvalidWorkerCount, encodeFile(io, testing.allocator, input, 0, output, 17));
    const empty_root = try encodeFile(io, testing.allocator, input, 0, output, 16);
    var empty_expected: Bough.Hash = undefined;
    std.crypto.hash.Blake3.hash(&.{}, &empty_expected, .{});
    try testing.expectEqualSlices(u8, &empty_expected, &empty_root);
    try testing.expectEqual(@as(u64, 8), (try output.stat(io)).size);
    // The regular 256-chunk minimum keeps these in a single ROOT segment.
    const small = [_]u8{42};
    try input.writePositionalAll(io, &small, 0);
    const root = try encodeFile(io, testing.allocator, input, 1, output, 16);
    var expected: Bough.Hash = undefined;
    std.crypto.hash.Blake3.hash(&small, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &root);
    const one_worker_root = try encodeFile(io, testing.allocator, input, 1, output, 1);
    try testing.expectEqualSlices(u8, &root, &one_worker_root);
    try testing.expectError(error.UnexpectedEof, encodeFile(io, testing.allocator, input, Bough.chunk_length + 1, output, 2));
}

test "non-regular files are rejected before output changes" {
    if (@import("builtin").os.tag != .linux) return;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var input = try tmp.dir.createFile(io, "in", .{ .read = true });
    defer input.close(io);
    var output = try tmp.dir.createFile(io, "out", .{ .read = true });
    defer output.close(io);
    try output.setLength(io, 123);

    // /dev/null has positional operations on some platforms but is not a
    // regular file; reject it even for an empty input (zero worker threads).
    var device = try std.Io.Dir.cwd().openFile(io, "/dev/null", .{ .mode = .read_write });
    defer device.close(io);
    try testing.expectError(error.NotRegularFile, encodeFile(io, testing.allocator, device, 0, output, 4));
    try testing.expectError(error.NotRegularFile, encodeFile(io, testing.allocator, input, 0, device, 4));
    try testing.expectEqual(@as(u64, 123), (try output.stat(io)).size);
}
