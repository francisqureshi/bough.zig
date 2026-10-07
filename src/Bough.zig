//! Bough: Bao-inspired verified streaming with BLAKE3-derived hashing.
//!
//! Gives us, for large-file sync:
//!   1. A 32-byte root hash for a file. Matches canonical BLAKE3 only for
//!      inputs up to 1 KiB; larger files use custom 256 KiB hashing chunks.
//!   2. An "outboard" sidecar of non-root internal Merkle node CVs.
//!   3. Slice extraction/verification and streaming content verification.
//!   4. Bounded parallel file encoding via Bough.Parallel.
//!
//! Bough sidecar format (NOT compatible with upstream Bao):
//!
//!   [ 8 bytes  ] content_length (little-endian u64)
//!   [ 32 × M   ] parent CVs in COMPUTE order (post-order DFS over internal
//!                nodes), the root excluded. M = max(0, n_chunks - 2).
//!
//! Bao canonical spec uses pre-order; we use post-order so encoding streams
//! without buffering the whole tree. Conversion is mechanical via an offset
//! table when we need spec interop.
//!
//! Spec reference: https://github.com/oconnor663/bao/blob/master/docs/spec.md

const std = @import("std");
const blake3 = @import("blake3_lo.zig");

const Bough = @This();

pub const Hash = [blake3.digest_length]u8;
/// Bounded worker-thread encoding into a positional outboard file.
pub const Parallel = @import("Parallel.zig");

test {
    _ = Parallel;
}
/// Re-exported so callers can size splits/buffers in chunks without reaching
/// into blake3_lo.
pub const chunk_length = blake3.chunk_length;
// 1 MiB: must be >= chunk_length (256 KiB) so a chunk fills in one underlying
// read instead of several. The encoder batches reads of up to simd_degree
// chunks and hashes them via SIMD; Parallel schedules independent subtrees.
pub const READ_BUF_SIZE = 1024 * 1024;

const log = std.log.scoped(.bough);

pub const Encoded = struct {
    root: Hash,
    content_length: u64,
    n_chunks: u64,
    n_internal: u64,
};

/// Encode a file by path: opens, encodes, returns root + counts.
pub fn encodeFile(
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    out_writer: *std.Io.Writer,
) !Encoded {
    var file = try dir.openFile(io, name, .{});
    defer file.close(io);
    const stat = try file.stat(io);

    var read_buf: [READ_BUF_SIZE]u8 align(8) = undefined;
    var fr = file.readerStreaming(io, &read_buf);
    return encodeReader(&fr.interface, stat.size, out_writer);
}

/// Core encoder: stream `content_length` bytes from `r`, emit outboard to
/// `out_writer`, return root + counts.
///
/// Batched reads hash known non-final chunks via `hashManyContiguous`.
/// The declared length identifies the final chunk without lookahead or
/// moving a carry buffer. ROOT goes on that chunk (single-chunk file) or on
/// the final parent merge that includes it (multi-chunk file). Root CV is
/// NOT emitted to the outboard — the verifier reconstructs it from its
/// children.
pub fn encodeReader(
    r: *std.Io.Reader,
    content_length: u64,
    out_writer: *std.Io.Writer,
) !Encoded {
    // Header.
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u64, &hdr, content_length, .little);
    try out_writer.writeAll(&hdr);

    // Empty file: BLAKE3 of empty input.
    if (content_length == 0) {
        var out: Hash = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &out, .{});
        return .{ .root = out, .content_length = 0, .n_chunks = 0, .n_internal = 0 };
    }

    // The whole file is one root subtree: counter base 0, ROOT applied, root
    // CV suppressed. `content_length` bytes == the entire reader.
    const res = try encodeSubtreeCore(r, content_length, 0, true, out_writer);
    return .{
        .root = blake3.cvWordsToBytes(res.root),
        .content_length = content_length,
        .n_chunks = res.n_chunks,
        .n_internal = res.n_internal,
    };
}

const SubtreeResult = struct {
    root: [8]u32,
    n_chunks: u64,
    n_internal: u64,
};

/// Encode a single BLAKE3 subtree spanning exactly `segment_len` bytes read
/// from `r`, emitting its interior parent CVs (post-order) to `out`. Shared
/// core of `encodeReader` (whole file, root subtree) and the parallel
/// `encodeSubtree` (one segment of a larger file).
///
///   - `start_counter` seeds the BLAKE3 chunk counter — ESSENTIAL, since the
///     counter is mixed into every chunk compression. A segment starting at
///     chunk `k·C` must pass `start_counter = k·C`.
///   - Merge/popcount decisions use the LOCAL chunk index, so the subtree's
///     shape is independent of where it sits in the file.
///   - `is_root`: the final combine gets the ROOT flag and is NOT emitted
///     (matches the old `encodeReader`). Otherwise the final combine is this
///     subtree's root — emitted as the last interior CV and returned so the
///     combiner can splice it at the super level.
fn encodeSubtreeCore(
    r: *std.Io.Reader,
    segment_len: u64,
    start_counter: u64,
    is_root: bool,
    out: *std.Io.Writer,
) !SubtreeResult {
    std.debug.assert(segment_len > 0);

    // CV stack of completed subtrees, popcount(chunks_processed) invariant.
    var stack: [55][8]u32 = undefined;
    var stack_len: usize = 0;
    var n_internal: u64 = 0;

    // The exact length lets us reserve the last chunk without copying it
    // between batches. Reuse the batch buffer for the final scalar chunk.
    const BATCH_CHUNKS = blake3.simd_degree;
    var buf: [BATCH_CHUNKS * blake3.chunk_length]u8 = undefined;
    var counter = start_counter;
    var local: u64 = 0;
    const nonfinal_chunks = (segment_len - 1) / blake3.chunk_length;

    while (local < nonfinal_chunks) {
        const hashable: usize = @intCast(@min(BATCH_CHUNKS, nonfinal_chunks - local));
        const want = hashable * blake3.chunk_length;
        if (try r.readSliceShort(buf[0..want]) != want) return error.UnexpectedEof;
        var cvs: [BATCH_CHUNKS][8]u32 = undefined;
        blake3.hashManyContiguous(buf[0..want], counter, blake3.iv, cvs[0..hashable]);
        for (cvs[0..hashable]) |cv| {
            stack[stack_len] = cv;
            stack_len += 1;

            const processed = local + 1;
            const target_len: usize = @popCount(processed);
            while (stack_len > target_len) {
                const left = stack[stack_len - 2];
                const right = stack[stack_len - 1];
                const parent = blake3.parentHash(left, right, blake3.iv, .{});
                stack[stack_len - 2] = parent;
                stack_len -= 1;
                try writeCv(out, parent);
                n_internal += 1;
            }
            counter += 1;
            local += 1;
        }
    }

    const carry_len: usize = @intCast(segment_len - local * blake3.chunk_length);
    if (try r.readSliceShort(buf[0..carry_len]) != carry_len) return error.UnexpectedEof;
    const total_chunks: u64 = local + 1;

    // Single-chunk subtree: the carry IS the whole subtree.
    if (total_chunks == 1) {
        const cv = blake3.chunkHash(buf[0..carry_len], counter, blake3.iv, .{ .root = is_root });
        return .{ .root = cv, .n_chunks = 1, .n_internal = 0 };
    }

    // Multi-chunk: hash last chunk WITHOUT ROOT, then climb the stack pairing
    // it with each pending subtree. The topmost merge is this subtree's root:
    // it gets ROOT (and is suppressed) only when `is_root`; otherwise it is a
    // plain interior CV — emitted like the rest.
    var current = blake3.chunkHash(buf[0..carry_len], counter, blake3.iv, .{});
    while (stack_len > 0) {
        const left = stack[stack_len - 1];
        stack_len -= 1;
        const is_top = (stack_len == 0);
        const root_here = is_top and is_root;
        const parent = blake3.parentHash(
            left,
            current,
            blake3.iv,
            if (root_here) .{ .root = true } else .{},
        );
        if (!root_here) {
            try writeCv(out, parent);
            n_internal += 1;
        }
        current = parent;
    }

    return .{ .root = current, .n_chunks = total_chunks, .n_internal = n_internal };
}

/// Encode one subtree segment for parallel outboard construction. Reads
/// exactly `segment_len` bytes from `r`; emits its interior CVs to `out`;
/// returns the segment's root CV (words). No header. Pass `start_counter =
/// segment.startCounter()` and `is_root = (n_segments == 1)`. See
/// `encodeSubtreeCore` and `combineSubtrees`.
pub fn encodeSubtree(
    r: *std.Io.Reader,
    start_counter: u64,
    segment_len: u64,
    is_root: bool,
    out: *std.Io.Writer,
) ![8]u32 {
    const res = try encodeSubtreeCore(r, segment_len, start_counter, is_root, out);
    return res.root;
}

fn writeCv(out: *std.Io.Writer, cv_words: [8]u32) !void {
    const bytes = blake3.cvWordsToBytes(cv_words);
    try out.writeAll(&bytes);
}

// -----------------------------------------------------------------------------
// Parallel subtree split + combine (issue #142).
//
// BLAKE3's tree is left-full: for a power-of-two chunk count C = 2^m, the range
// [k·C, (k+1)·C) is always a perfect C-chunk subtree, and the global split point
// L = largest_pow2 < N is a multiple of C (since N > C ⇒ L ≥ C). So a file of N
// chunks splits into P = ceil(N/C) subtree-aligned segments (the first P-1 full,
// the last the 1..C-chunk remainder), each encodable independently. The combiner
// splices the per-segment interior-CV runs and merges the segment roots at the
// "super level" — literally `encodeReader` over the segment roots, driven by the
// SEGMENT index (popcount((k+1)·C) == popcount(k+1)), with the last segment as
// the carry so the global root is suppressed. Emitted CV count is unchanged:
// (N − P) segment-interior CVs + (P − 2) super CVs = N − 2.
// -----------------------------------------------------------------------------

/// Minimum chunks per segment: below this, subtree parallelism isn't worth the
/// per-segment overhead, so tiny files fall back to a single segment (P=1).
pub const MIN_SEG_CHUNKS: u64 = 256;

/// Largest power of two ≤ x (x ≥ 1).
fn floorPow2(x: u64) u64 {
    std.debug.assert(x >= 1);
    var p: u64 = 1;
    while (p <= x >> 1) p <<= 1;
    return p;
}

pub const Segment = struct {
    start_chunk: u64,
    chunk_count: u64,

    /// BLAKE3 chunk counter for this segment's first chunk.
    pub fn startCounter(self: Segment) u64 {
        return self.start_chunk;
    }
    /// Byte offset of the segment's first chunk.
    pub fn byteStart(self: Segment) u64 {
        return self.start_chunk * blake3.chunk_length;
    }
    /// Byte length to read for this segment, given the whole content length
    /// (the last chunk of the last segment may be partial).
    pub fn byteLen(self: Segment, content_length: u64) u64 {
        const start = self.byteStart();
        const end = @min(start + self.chunk_count * blake3.chunk_length, content_length);
        return end - start;
    }
};

pub const Split = struct {
    /// Chunks per full segment — a power of two. 0 iff the file is empty.
    seg_chunks: u64,
    total_chunks: u64,

    /// Number of segments P = ceil(N / C).
    pub fn count(self: Split) u64 {
        if (self.total_chunks == 0) return 0;
        return (self.total_chunks + self.seg_chunks - 1) / self.seg_chunks;
    }
    pub fn segment(self: Split, k: u64) Segment {
        const start = k * self.seg_chunks;
        std.debug.assert(start < self.total_chunks);
        return .{ .start_chunk = start, .chunk_count = @min(self.seg_chunks, self.total_chunks - start) };
    }

    /// Byte offset of segment k's interior-CV run in the final outboard —
    /// lets each lane pwrite its run directly, no in-memory splice.
    ///
    /// What precedes blob k in the post-order stream: the 8-byte header, the
    /// interior runs of segments 0..k (all full, C chunks ⇒ C−1 CVs each ⇒
    /// k·(C−1) total), and the super-level parent CVs already emitted. The
    /// super level runs encodeReader's stack algorithm over the segment
    /// roots: after k pushes the stack holds popCount(k) entries, so exactly
    /// k − popCount(k) merges (= super CVs) have happened. Total:
    ///   8 + 32·(k·(C−1) + k − popCount(k)) = 8 + 32·(k·C − popCount(k)).
    pub fn segmentOutboardOffset(self: Split, k: u64) u64 {
        std.debug.assert(k < self.count());
        return 8 + 32 * (k * self.seg_chunks - @popCount(k));
    }
};

/// Split `n_chunks` into ~`target` subtree-aligned segments. Segment size C is
/// the largest power of two ≤ n_chunks/target, clamped up to MIN_SEG_CHUNKS.
/// Every full segment is a perfect C-chunk subtree; the last is the remainder
/// (1..C chunks). When n_chunks is large enough that the ratio (not the clamp)
/// sets C, the segment count P lands in [target, 2·target).
pub fn subtreeSplit(n_chunks: u64, target: u64) Split {
    std.debug.assert(target >= 1);
    if (n_chunks == 0) return .{ .seg_chunks = 0, .total_chunks = 0 };
    const ratio = n_chunks / target;
    var c: u64 = if (ratio >= 1) floorPow2(ratio) else 1;
    if (c < MIN_SEG_CHUNKS) c = MIN_SEG_CHUNKS;
    return .{ .seg_chunks = c, .total_chunks = n_chunks };
}

/// Combine per-segment encode results into one outboard byte-identical to
/// `encodeReader`. `seg_roots[k]` / `seg_blobs[k]` are the root CV and interior
/// CV bytes returned/emitted by `encodeSubtree` on `split.segment(k)`. Writes
/// the 8-byte header then the interleaved post-order CV stream; returns the
/// file root.
pub fn combineSubtrees(
    split: Split,
    content_length: u64,
    seg_roots: []const [8]u32,
    seg_blobs: []const []const u8,
    out: *std.Io.Writer,
) !Hash {
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u64, &hdr, content_length, .little);
    try out.writeAll(&hdr);

    const p = split.count();
    if (p == 0) {
        var o: Hash = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &o, .{});
        return o;
    }
    std.debug.assert(seg_roots.len == p and seg_blobs.len == p);

    // Single segment: it IS the root subtree (encoded with is_root=true), so
    // its blob is already the whole CV stream and its root is the file root.
    if (p == 1) {
        try out.writeAll(seg_blobs[0]);
        return blake3.cvWordsToBytes(seg_roots[0]);
    }

    // Super level: run encodeReader's stack algorithm over the segment roots,
    // driven by segment index. Splice each segment's interior CVs BEFORE its
    // push/merge so the post-order interleaving matches the sequential encoder.
    var stack: [55][8]u32 = undefined;
    var stack_len: usize = 0;

    var k: u64 = 0;
    while (k + 1 < p) : (k += 1) {
        try out.writeAll(seg_blobs[@intCast(k)]);
        stack[stack_len] = seg_roots[@intCast(k)];
        stack_len += 1;

        const processed = k + 1;
        const target_len: usize = @popCount(processed);
        while (stack_len > target_len) {
            const left = stack[stack_len - 2];
            const right = stack[stack_len - 1];
            const parent = blake3.parentHash(left, right, blake3.iv, .{});
            stack[stack_len - 2] = parent;
            stack_len -= 1;
            try writeCv(out, parent);
        }
    }

    // Last segment = carry: splice its interiors, then climb, ROOT on the top.
    try out.writeAll(seg_blobs[@intCast(p - 1)]);
    var current = seg_roots[@intCast(p - 1)];
    while (stack_len > 0) {
        const left = stack[stack_len - 1];
        stack_len -= 1;
        const is_top = (stack_len == 0);
        const parent = blake3.parentHash(left, current, blake3.iv, if (is_top) .{ .root = true } else .{});
        if (!is_top) try writeCv(out, parent);
        current = parent;
    }
    return blake3.cvWordsToBytes(current);
}

/// Positional variant of `combineSubtrees` for direct-to-file assembly: the
/// per-segment interior-CV runs are already in the outboard file (each lane
/// pwrites its run at `split.segmentOutboardOffset(k)`), so all that remains
/// is the 8-byte header and the P−2 super-level parent CVs. Same merge order
/// as the streaming version, but instead of splicing blobs a running offset
/// advances past each segment's interior run and each super CV is pwritten
/// where the stream would have put it — no buffer proportional to file size.
/// Returns the file root.
pub fn combineSubtreesPositional(
    split: Split,
    content_length: u64,
    seg_roots: []const [8]u32,
    io: std.Io,
    out: std.Io.File,
) !Hash {
    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u64, &hdr, content_length, .little);
    try out.writePositionalAll(io, &hdr, 0);

    const p = split.count();
    if (p == 0) {
        var o: Hash = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &o, .{});
        return o;
    }
    std.debug.assert(seg_roots.len == p);

    // Single segment: it IS the root subtree (encoded with is_root=true), so
    // its on-disk run is already the whole CV stream and its root is the
    // file root. Nothing left but the header.
    if (p == 1) return blake3.cvWordsToBytes(seg_roots[0]);

    // Super level: encodeReader's stack algorithm over the segment roots.
    // `off` tracks where the next CV would land in the sequential stream;
    // each segment's interior run (chunk_count − 1 CVs, already on disk)
    // just advances it.
    var stack: [55][8]u32 = undefined;
    var stack_len: usize = 0;
    var off: u64 = 8;

    var k: u64 = 0;
    while (k + 1 < p) : (k += 1) {
        std.debug.assert(off == split.segmentOutboardOffset(k));
        off += 32 * (split.segment(k).chunk_count - 1);
        stack[stack_len] = seg_roots[@intCast(k)];
        stack_len += 1;

        const processed = k + 1;
        const target_len: usize = @popCount(processed);
        while (stack_len > target_len) {
            const left = stack[stack_len - 2];
            const right = stack[stack_len - 1];
            const parent = blake3.parentHash(left, right, blake3.iv, .{});
            stack[stack_len - 2] = parent;
            stack_len -= 1;
            const bytes = blake3.cvWordsToBytes(parent);
            try out.writePositionalAll(io, &bytes, off);
            off += 32;
        }
    }

    // Last segment = carry: skip its interior run, then climb, ROOT on top.
    std.debug.assert(off == split.segmentOutboardOffset(p - 1));
    off += 32 * (split.segment(p - 1).chunk_count - 1);
    var current = seg_roots[@intCast(p - 1)];
    while (stack_len > 0) {
        const left = stack[stack_len - 1];
        stack_len -= 1;
        const is_top = (stack_len == 0);
        const parent = blake3.parentHash(left, current, blake3.iv, if (is_top) .{ .root = true } else .{});
        if (!is_top) {
            const bytes = blake3.cvWordsToBytes(parent);
            try out.writePositionalAll(io, &bytes, off);
            off += 32;
        }
        current = parent;
    }
    // Stream complete: N−2 CVs total, exactly as the sequential encoder.
    std.debug.assert(off == 8 + 32 * (split.total_chunks - 2));
    return blake3.cvWordsToBytes(current);
}

// -----------------------------------------------------------------------------
// In-memory pre-order tree + slice extract + verify.
//
// The streaming `encodeReader` above is for production-scale persistence
// (no full tree in RAM). The in-memory `Tree` here is for slice operations
// — extract a verifiable byte range from a file given its tree. Trades
// memory for traversal simplicity. For 100 GB files, the tree is ~12 MB
// (256 KiB chunks) — production may still prefer a seekable on-disk
// pre-order outboard. Same math, different storage.
//
// Tree layout: pre-order DFS over internal nodes.
//   cvs[0]    = root's-left-child's-... = first internal CV visited
//   cvs[i]    = subtree CVs in DFS pre-order
//   cvs[N-1]  = last internal CV
// Total internal nodes = n_chunks - 1.
//
// Slice format (post-header):
//   For each internal node visited on the way down to a touched leaf:
//     - If the OTHER subtree is fully outside the requested range:
//         emit its CV (32 bytes proof).
//     - Else: don't emit (verifier descends into both).
//   For each touched leaf chunk:
//     - Emit the raw chunk bytes (1..chunk_length bytes).
//
// The verifier walks the same tree shape (derived from content_length +
// offset + len), reading proof CVs / chunk bytes from the slice, computes
// chunk CVs from received bytes, combines up the tree, compares to root
// (with ROOT flag on the topmost combine).
// -----------------------------------------------------------------------------

pub const Tree = struct {
    root: Hash,
    content_length: u64,
    n_chunks: u64,
    /// Internal node CVs in pre-order, EXCLUDING the root (verifier
    /// reconstructs root from its two children). Length = max(0, n_chunks - 2).
    cvs: []Hash,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *Tree) void {
        self.alloc.free(self.cvs);
    }
};

fn chunksOf(content_len: u64) u64 {
    if (content_len == 0) return 0;
    return (content_len - 1) / blake3.chunk_length + 1;
}

fn outboardSize(n_internal: u64) !u64 {
    const cv_bytes = try std.math.mul(u64, 32, n_internal);
    return std.math.add(u64, 8, cv_bytes);
}

/// Left subtree size in chunks: largest power of 2 < chunk_count.
fn leftSubtreeChunks(chunk_count: u64) u64 {
    std.debug.assert(chunk_count >= 2);
    var p: u64 = 1;
    while (p * 2 < chunk_count) p *= 2;
    return p;
}

/// Build the full in-memory tree from a content slice.
pub fn buildTree(alloc: std.mem.Allocator, content: []const u8) !Tree {
    if (content.len == 0) {
        var out: Hash = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &out, .{});
        return .{
            .root = out,
            .content_length = 0,
            .n_chunks = 0,
            .cvs = &.{},
            .alloc = alloc,
        };
    }

    const n_chunks = chunksOf(content.len);
    const n_internal: usize = if (n_chunks <= 1) 0 else @intCast(n_chunks - 2);
    const cvs = try alloc.alloc(Hash, n_internal);
    errdefer alloc.free(cvs);

    var cursor: usize = 0;
    const root_cv = buildSubtree(content, 0, n_chunks, true, cvs, &cursor);
    std.debug.assert(cursor == n_internal);

    return .{
        .root = blake3.cvWordsToBytes(root_cv),
        .content_length = content.len,
        .n_chunks = n_chunks,
        .cvs = cvs,
        .alloc = alloc,
    };
}

/// Recursive pre-order tree builder. For non-root internal nodes, reserves a
/// slot in `cv_out` BEFORE recursing (so parent CV comes before its subtree
/// in pre-order). Root has no slot — caller takes its CV directly.
fn buildSubtree(
    content: []const u8,
    chunk_start: u64,
    chunk_count: u64,
    is_root: bool,
    cv_out: []Hash,
    cv_cursor: *usize,
) [8]u32 {
    std.debug.assert(chunk_count >= 1);
    if (chunk_count == 1) {
        const off: usize = @intCast(chunk_start * blake3.chunk_length);
        const end: usize = @intCast(@min(@as(u64, off) + blake3.chunk_length, content.len));
        const chunk_bytes = content[off..end];
        const flags: blake3.Flags = if (is_root) .{ .root = true } else .{};
        return blake3.chunkHash(chunk_bytes, chunk_start, blake3.iv, flags);
    }

    const left_chunks = leftSubtreeChunks(chunk_count);
    const right_chunks = chunk_count - left_chunks;

    // Non-root parents get a slot in cv_out, reserved before recursion.
    var my_slot: ?usize = null;
    if (!is_root) {
        my_slot = cv_cursor.*;
        cv_cursor.* += 1;
    }

    const left_cv = buildSubtree(content, chunk_start, left_chunks, false, cv_out, cv_cursor);
    const right_cv = buildSubtree(content, chunk_start + left_chunks, right_chunks, false, cv_out, cv_cursor);

    const parent_flags: blake3.Flags = if (is_root) .{ .root = true } else .{};
    const parent_cv = blake3.parentHash(left_cv, right_cv, blake3.iv, parent_flags);

    if (my_slot) |slot| cv_out[slot] = blake3.cvWordsToBytes(parent_cv);
    return parent_cv;
}

// ---- slice extract/verify ----

/// Slice header: tells verifier the tree shape (via content_length) and
/// which range to expect.
pub const SliceHeader = struct {
    content_length: u64,
    offset: u64,
    len: u64,

    pub fn writeTo(self: SliceHeader, w: *std.Io.Writer) !void {
        var buf: [24]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.content_length, .little);
        std.mem.writeInt(u64, buf[8..16], self.offset, .little);
        std.mem.writeInt(u64, buf[16..24], self.len, .little);
        try w.writeAll(&buf);
    }

    pub fn readFrom(r: *std.Io.Reader) !SliceHeader {
        var buf: [24]u8 = undefined;
        const n = try r.readSliceShort(&buf);
        if (n != 24) return error.SliceTruncated;
        return .{
            .content_length = std.mem.readInt(u64, buf[0..8], .little),
            .offset = std.mem.readInt(u64, buf[8..16], .little),
            .len = std.mem.readInt(u64, buf[16..24], .little),
        };
    }
};

/// Emit a verifiable slice covering `[offset, offset+len)` from `content`
/// using `tree`. Format: header (24 bytes), then pre-order traversal of the
/// tree emitting one of two things at each subtree:
///   - Untouched subtree → 32 bytes proof CV (parent CV from tree, or leaf
///     chunk CV computed from content for 1-chunk subtrees).
///   - Touched leaf → raw chunk bytes (up to chunk_length).
///   - Touched internal → recurse (no emission for this node itself).
pub fn extractSlice(
    tree: Tree,
    content: []const u8,
    offset: u64,
    len: u64,
    out: *std.Io.Writer,
) !void {
    if (offset + len > tree.content_length) return error.RangeOutOfFile;

    const header: SliceHeader = .{
        .content_length = tree.content_length,
        .offset = offset,
        .len = len,
    };
    try header.writeTo(out);

    if (tree.content_length == 0) return;

    const req_start_chunk = offset / blake3.chunk_length;
    const req_end_chunk = if (len == 0)
        req_start_chunk
    else
        (offset + len + blake3.chunk_length - 1) / blake3.chunk_length;

    var cursor: usize = 0;
    try walkExtract(
        content,
        tree.cvs,
        &cursor,
        0,
        tree.n_chunks,
        req_start_chunk,
        req_end_chunk,
        out,
    );
}

const ExtractError = error{NoOverlap} || std.Io.Writer.Error;

fn walkExtract(
    content: []const u8,
    cvs: []const Hash,
    cv_cursor: *usize,
    chunk_start: u64,
    chunk_count: u64,
    req_start: u64,
    req_end: u64,
    out: *std.Io.Writer,
) ExtractError!void {
    const subtree_end = chunk_start + chunk_count;
    const touched = @max(chunk_start, req_start) < @min(subtree_end, req_end);

    if (chunk_count == 1) {
        if (touched) {
            const off: usize = @intCast(chunk_start * blake3.chunk_length);
            const end: usize = @intCast(@min(@as(u64, off) + blake3.chunk_length, content.len));
            try out.writeAll(content[off..end]);
        } else {
            // Untouched leaf: emit its CV as proof.
            const off: usize = @intCast(chunk_start * blake3.chunk_length);
            const end: usize = @intCast(@min(@as(u64, off) + blake3.chunk_length, content.len));
            const cv = blake3.chunkHash(content[off..end], chunk_start, blake3.iv, .{});
            const bytes = blake3.cvWordsToBytes(cv);
            try out.writeAll(&bytes);
        }
        return;
    }

    // Internal subtree. Advance past its own slot in cvs (the slot exists
    // only for non-root nodes — caller of walkExtract advances cursor for
    // its own slot, so we consume our slot here uniformly for non-root.
    // Root is the FIRST call into walkExtract; root has no slot. We detect
    // root via chunk_start==0 and chunk_count==tree.n_chunks at the call
    // site — handled by NOT advancing cursor at the top level call (i.e.
    // walkExtract assumes its slot has already been "consumed" by the
    // caller's context). For internal recursion below, we advance.

    const left_chunks = leftSubtreeChunks(chunk_count);
    const left_end = chunk_start + left_chunks;
    const right_chunks = chunk_count - left_chunks;
    const left_touched = @max(chunk_start, req_start) < @min(left_end, req_end);
    const right_touched = @max(left_end, req_start) < @min(subtree_end, req_end);

    if (left_touched and right_touched) {
        // Both children touched — recurse into both. Advance their own slots
        // as we go.
        try walkInternalChild(content, cvs, cv_cursor, chunk_start, left_chunks, req_start, req_end, out);
        try walkInternalChild(content, cvs, cv_cursor, left_end, right_chunks, req_start, req_end, out);
    } else if (left_touched) {
        try walkInternalChild(content, cvs, cv_cursor, chunk_start, left_chunks, req_start, req_end, out);
        try writeProofForSubtree(content, cvs, cv_cursor, left_end, right_chunks, out);
    } else if (right_touched) {
        try writeProofForSubtree(content, cvs, cv_cursor, chunk_start, left_chunks, out);
        try walkInternalChild(content, cvs, cv_cursor, left_end, right_chunks, req_start, req_end, out);
    } else {
        // Range was wholly inside one of these subtrees, called from above
        // with both untouched — unreachable from extractSlice top-level.
        return error.NoOverlap;
    }
}

/// Recurse into a child subtree. If the child is a non-leaf internal node,
/// consume its slot in cvs first (it lives at cv_cursor*). Then recurse.
fn walkInternalChild(
    content: []const u8,
    cvs: []const Hash,
    cv_cursor: *usize,
    chunk_start: u64,
    chunk_count: u64,
    req_start: u64,
    req_end: u64,
    out: *std.Io.Writer,
) ExtractError!void {
    if (chunk_count >= 2) cv_cursor.* += 1;
    try walkExtract(content, cvs, cv_cursor, chunk_start, chunk_count, req_start, req_end, out);
}

/// Emit a 32-byte proof CV for an untouched subtree. For ≥2-chunk subtrees,
/// the CV comes from `cvs` at the current cursor; advance past the subtree.
/// For 1-chunk subtrees, compute the leaf CV from content.
fn writeProofForSubtree(
    content: []const u8,
    cvs: []const Hash,
    cv_cursor: *usize,
    chunk_start: u64,
    chunk_count: u64,
    out: *std.Io.Writer,
) !void {
    if (chunk_count == 1) {
        const off: usize = @intCast(chunk_start * blake3.chunk_length);
        const end: usize = @intCast(@min(@as(u64, off) + blake3.chunk_length, content.len));
        const cv = blake3.chunkHash(content[off..end], chunk_start, blake3.iv, .{});
        const bytes = blake3.cvWordsToBytes(cv);
        try out.writeAll(&bytes);
        return;
    }
    const slot = cv_cursor.*;
    try out.writeAll(&cvs[slot]);
    // Skip past this entire subtree's internal nodes (n_chunks - 1 of them).
    cv_cursor.* = slot + @as(usize, @intCast(chunk_count - 1));
}

/// Verify a slice against `claimed_root`. Reads header (which dictates tree
/// shape), then walks the same DFS as extractor, consuming proof CVs and
/// content bytes, recomputing parent CVs, and finally comparing the
/// reconstructed root against `claimed_root`.
///
/// Returns the verified content bytes via `range_out` (caller-provided buf
/// large enough to hold `header.len` bytes).
pub fn verifySlice(
    slice_r: *std.Io.Reader,
    claimed_root: Hash,
    range_out: []u8,
) !SliceHeader {
    const header = try SliceHeader.readFrom(slice_r);
    if (header.len > range_out.len) return error.RangeBufTooSmall;

    if (header.content_length == 0) {
        // Empty file root.
        var expected: Hash = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &expected, .{});
        if (!std.mem.eql(u8, &expected, &claimed_root)) return error.RootMismatch;
        return header;
    }

    const n_chunks = chunksOf(header.content_length);
    const req_start = header.offset / blake3.chunk_length;
    const req_end = if (header.len == 0)
        req_start
    else
        (header.offset + header.len + blake3.chunk_length - 1) / blake3.chunk_length;

    var write_off: usize = 0;
    const root_cv = try walkVerify(
        slice_r,
        header,
        range_out,
        &write_off,
        0,
        n_chunks,
        req_start,
        req_end,
        true,
    );

    const got = blake3.cvWordsToBytes(root_cv);
    if (!std.mem.eql(u8, &got, &claimed_root)) return error.RootMismatch;
    return header;
}

const VerifyError = error{ NoOverlap, RootMismatch, SliceTruncated, ReadFailed };

fn walkVerify(
    slice_r: *std.Io.Reader,
    header: SliceHeader,
    range_out: []u8,
    write_off: *usize,
    chunk_start: u64,
    chunk_count: u64,
    req_start: u64,
    req_end: u64,
    is_root: bool,
) VerifyError![8]u32 {
    const subtree_end = chunk_start + chunk_count;
    const touched = @max(chunk_start, req_start) < @min(subtree_end, req_end);

    if (chunk_count == 1) {
        if (touched) {
            // Read chunk bytes, hash, optionally copy the requested sub-range
            // into range_out.
            const chunk_off = chunk_start * blake3.chunk_length;
            const chunk_end = @min(chunk_off + blake3.chunk_length, header.content_length);
            const chunk_len: usize = @intCast(chunk_end - chunk_off);
            var chunk_buf: [blake3.chunk_length]u8 = undefined;
            const got = try slice_r.readSliceShort(chunk_buf[0..chunk_len]);
            if (got != chunk_len) return error.SliceTruncated;
            const chunk_bytes = chunk_buf[0..chunk_len];

            // Copy any part of this chunk that's inside [header.offset, header.offset+header.len)
            // into range_out.
            const req_lo = header.offset;
            const req_hi = header.offset + header.len;
            const copy_lo = @max(chunk_off, req_lo);
            const copy_hi = @min(chunk_end, req_hi);
            if (copy_lo < copy_hi) {
                const src_start: usize = @intCast(copy_lo - chunk_off);
                const src_end: usize = @intCast(copy_hi - chunk_off);
                const dst_start: usize = @intCast(copy_lo - req_lo);
                const n: usize = src_end - src_start;
                @memcpy(range_out[dst_start..][0..n], chunk_bytes[src_start..src_end]);
                write_off.* = @max(write_off.*, dst_start + n);
            }

            const flags: blake3.Flags = if (is_root) .{ .root = true } else .{};
            return blake3.chunkHash(chunk_bytes, chunk_start, blake3.iv, flags);
        } else {
            // Untouched leaf — slice carries its CV directly.
            var cv_bytes: Hash = undefined;
            const got = try slice_r.readSliceShort(&cv_bytes);
            if (got != 32) return error.SliceTruncated;
            return blake3.cvBytesToWords(cv_bytes);
        }
    }

    const left_chunks = leftSubtreeChunks(chunk_count);
    const right_chunks = chunk_count - left_chunks;
    const left_end = chunk_start + left_chunks;
    const left_touched = @max(chunk_start, req_start) < @min(left_end, req_end);
    const right_touched = @max(left_end, req_start) < @min(subtree_end, req_end);

    var left_cv: [8]u32 = undefined;
    var right_cv: [8]u32 = undefined;

    if (left_touched and right_touched) {
        left_cv = try walkVerify(slice_r, header, range_out, write_off, chunk_start, left_chunks, req_start, req_end, false);
        right_cv = try walkVerify(slice_r, header, range_out, write_off, left_end, right_chunks, req_start, req_end, false);
    } else if (left_touched) {
        left_cv = try walkVerify(slice_r, header, range_out, write_off, chunk_start, left_chunks, req_start, req_end, false);
        right_cv = try readProofCv(slice_r);
    } else if (right_touched) {
        left_cv = try readProofCv(slice_r);
        right_cv = try walkVerify(slice_r, header, range_out, write_off, left_end, right_chunks, req_start, req_end, false);
    } else {
        return error.NoOverlap;
    }

    const flags: blake3.Flags = if (is_root) .{ .root = true } else .{};
    return blake3.parentHash(left_cv, right_cv, blake3.iv, flags);
}

fn readProofCv(slice_r: *std.Io.Reader) ![8]u32 {
    var cv_bytes: Hash = undefined;
    const got = try slice_r.readSliceShort(&cv_bytes);
    if (got != 32) return error.SliceTruncated;
    return blake3.cvBytesToWords(cv_bytes);
}

// -----------------------------------------------------------------------------
// OutboardReader — random-access reader for on-disk outboard sidecars.
//
// Outboard layout (see file header):
//   [8 bytes] content_length, little-endian u64
//   [32 × M ] parent CVs in POST-ORDER over internal nodes (root excluded).
//             M = max(0, n_chunks - 2) — the streaming encoder emits every
//             internal parent CV EXCEPT the root.
//
// Random access: we do NOT precompute a position table. Each consumer that
// needs a CV walks the tree shape in pre-order and tracks a post-order
// cursor as it descends; when it reaches the target subtree the cursor
// holds that subtree's index. The cursor advances in the same order the
// encoder emits, by construction.
//
// Byte offset of CV i = 8 + 32 * i.
// -----------------------------------------------------------------------------

pub const OutboardReader = struct {
    io: std.Io,
    file: std.Io.File,
    content_length: u64,
    n_chunks: u64,
    /// Total CVs stored in the outboard. Equals max(0, n_chunks - 2) — the
    /// root CV is intentionally excluded by the encoder.
    n_internal: u64,

    pub const OpenError = std.Io.File.OpenError ||
        std.Io.File.ReadPositionalError ||
        std.Io.File.StatError ||
        error{ OutboardTooShort, OutboardTruncated, OutboardOversized, Overflow };

    pub fn open(io: std.Io, dir: std.Io.Dir, path: []const u8) OpenError!OutboardReader {
        var file = try dir.openFile(io, path, .{});
        errdefer file.close(io);

        var hdr: [8]u8 = undefined;
        const got = try file.readPositionalAll(io, &hdr, 0);
        if (got != 8) return error.OutboardTooShort;
        const content_length = std.mem.readInt(u64, &hdr, .little);
        const n_chunks = chunksOf(content_length);
        const n_internal: u64 = if (n_chunks <= 1) 0 else n_chunks - 2;

        // An outboard has one exact structural layout for its content length.
        const expected_size = try outboardSize(n_internal);
        const stat = try file.stat(io);
        if (stat.size < expected_size) return error.OutboardTruncated;
        if (stat.size > expected_size) return error.OutboardOversized;

        return .{
            .io = io,
            .file = file,
            .content_length = content_length,
            .n_chunks = n_chunks,
            .n_internal = n_internal,
        };
    }

    pub fn close(self: *OutboardReader) void {
        self.file.close(self.io);
        self.* = undefined;
    }

    /// Read the CV at post-order index `idx` (0..n_internal-1).
    pub fn cvAt(self: *OutboardReader, idx: u64) !Hash {
        std.debug.assert(idx < self.n_internal);
        const offset: u64 = 8 + 32 * idx;
        var buf: Hash = undefined;
        const got = try self.file.readPositionalAll(self.io, &buf, offset);
        if (got != 32) return error.OutboardTruncated;
        return buf;
    }
};

/// Internal-node count contributed by a subtree of `chunk_count` chunks to
/// the post-order outboard. The subtree's OWN root counts (it gets a slot
/// unless it's the global root). For chunk_count <= 1, no slots.
inline fn internalCountInSubtree(chunk_count: u64) u64 {
    return if (chunk_count <= 1) 0 else chunk_count - 1;
}

// -----------------------------------------------------------------------------
// Slice extract / verified seek using a disk-resident outboard.
//
// Mirrors extractSlice + verifySlice but reads CVs from `OutboardReader` and
// chunk bytes from a positioned read on the content file. No in-memory tree.
// -----------------------------------------------------------------------------

const ExtractFromOutboardError = error{
    RangeOutOfFile,
    OutboardTruncated,
    SliceTruncated,
    ReadFailed,
} || std.Io.Writer.Error || std.Io.File.ReadPositionalError || std.Io.File.OpenError;

/// Same wire format as `extractSlice` — header + DFS pre-order proof CVs
/// and touched chunk bytes — but CV source is the on-disk outboard and
/// content bytes are read positionally.
pub fn extractSliceFromOutboard(
    io: std.Io,
    outboard: *OutboardReader,
    content: std.Io.File,
    offset: u64,
    len: u64,
    out: *std.Io.Writer,
) ExtractFromOutboardError!void {
    if (offset + len > outboard.content_length) return error.RangeOutOfFile;

    const header: SliceHeader = .{
        .content_length = outboard.content_length,
        .offset = offset,
        .len = len,
    };
    try header.writeTo(out);

    if (outboard.content_length == 0) return;

    const req_start_chunk = offset / blake3.chunk_length;
    const req_end_chunk = if (len == 0)
        req_start_chunk
    else
        (offset + len + blake3.chunk_length - 1) / blake3.chunk_length;

    // Cursor counts CVs in post-order. The global root has no slot — the
    // top-level walk starts with cursor=0 and treats the top call as root.
    var cursor: u64 = 0;
    try walkExtractOutboard(
        io,
        outboard,
        content,
        &cursor,
        0,
        outboard.n_chunks,
        req_start_chunk,
        req_end_chunk,
        true,
        out,
    );
}

/// Walk the tree shape in pre-order, emitting proof CVs for untouched
/// subtrees and chunk bytes for touched leaves. Advances `cursor` in
/// post-order so that AFTER the recursive call returns for a subtree
/// rooted at this call, `cursor` has been advanced past every CV slot
/// inside that subtree (including the subtree's own slot, unless it is
/// the global root).
fn walkExtractOutboard(
    io: std.Io,
    outboard: *OutboardReader,
    content: std.Io.File,
    cursor: *u64,
    chunk_start: u64,
    chunk_count: u64,
    req_start: u64,
    req_end: u64,
    is_root: bool,
    out: *std.Io.Writer,
) ExtractFromOutboardError!void {
    const subtree_end = chunk_start + chunk_count;
    const touched = @max(chunk_start, req_start) < @min(subtree_end, req_end);

    if (chunk_count == 1) {
        if (touched) {
            try writeChunkBytes(io, outboard, content, chunk_start, out);
        } else {
            try writeLeafProofCv(io, outboard, content, chunk_start, out);
        }
        return;
    }

    const left_chunks = leftSubtreeChunks(chunk_count);
    const right_chunks = chunk_count - left_chunks;
    const left_end = chunk_start + left_chunks;
    const left_touched = @max(chunk_start, req_start) < @min(left_end, req_end);
    const right_touched = @max(left_end, req_start) < @min(subtree_end, req_end);

    if (left_touched and right_touched) {
        try walkExtractOutboard(io, outboard, content, cursor, chunk_start, left_chunks, req_start, req_end, false, out);
        try walkExtractOutboard(io, outboard, content, cursor, left_end, right_chunks, req_start, req_end, false, out);
    } else if (left_touched) {
        try walkExtractOutboard(io, outboard, content, cursor, chunk_start, left_chunks, req_start, req_end, false, out);
        try emitProofForUntouchedSubtree(io, outboard, content, cursor, left_end, right_chunks, out);
    } else if (right_touched) {
        try emitProofForUntouchedSubtree(io, outboard, content, cursor, chunk_start, left_chunks, out);
        try walkExtractOutboard(io, outboard, content, cursor, left_end, right_chunks, req_start, req_end, false, out);
    } else {
        unreachable; // top-level checks RangeOutOfFile
    }

    // After processing both children, consume this subtree's own slot —
    // unless it's the global root (root has no slot in the outboard).
    if (!is_root) cursor.* += 1;
}

/// Emit a 32-byte proof CV for an untouched subtree at (chunk_start,
/// chunk_count) and advance `cursor` past every CV slot inside it.
fn emitProofForUntouchedSubtree(
    io: std.Io,
    outboard: *OutboardReader,
    content: std.Io.File,
    cursor: *u64,
    chunk_start: u64,
    chunk_count: u64,
    out: *std.Io.Writer,
) !void {
    if (chunk_count == 1) {
        try writeLeafProofCv(io, outboard, content, chunk_start, out);
        return;
    }
    // The subtree's own CV is the LAST slot in its internal range — the
    // root of the subtree comes after all its descendants in post-order.
    // Descendants count = (chunk_count - 1) - 1 = chunk_count - 2.
    const subtree_root_idx = cursor.* + (chunk_count - 2);
    const cv = try outboard.cvAt(subtree_root_idx);
    try out.writeAll(&cv);
    cursor.* += internalCountInSubtree(chunk_count);
}

fn writeChunkBytes(
    io: std.Io,
    outboard: *OutboardReader,
    content: std.Io.File,
    chunk_idx: u64,
    out: *std.Io.Writer,
) !void {
    const chunk_off = chunk_idx * blake3.chunk_length;
    const chunk_end = @min(chunk_off + blake3.chunk_length, outboard.content_length);
    const chunk_len: usize = @intCast(chunk_end - chunk_off);
    var buf: [blake3.chunk_length]u8 = undefined;
    const got = try content.readPositionalAll(io, buf[0..chunk_len], chunk_off);
    if (got != chunk_len) return error.SliceTruncated;
    try out.writeAll(buf[0..chunk_len]);
}

fn writeLeafProofCv(
    io: std.Io,
    outboard: *OutboardReader,
    content: std.Io.File,
    chunk_idx: u64,
    out: *std.Io.Writer,
) !void {
    const chunk_off = chunk_idx * blake3.chunk_length;
    const chunk_end = @min(chunk_off + blake3.chunk_length, outboard.content_length);
    const chunk_len: usize = @intCast(chunk_end - chunk_off);
    var buf: [blake3.chunk_length]u8 = undefined;
    const got = try content.readPositionalAll(io, buf[0..chunk_len], chunk_off);
    if (got != chunk_len) return error.SliceTruncated;
    const cv = blake3.chunkHash(buf[0..chunk_len], chunk_idx, blake3.iv, .{});
    const bytes = blake3.cvWordsToBytes(cv);
    try out.writeAll(&bytes);
}

/// Hash a file without producing an outboard. Streams the file once and
/// discards everything except the root CV. Same root hash as `encodeFile`.
pub fn hashFile(io: std.Io, dir: std.Io.Dir, name: []const u8) !Hash {
    var file = try dir.openFile(io, name, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    var read_buf: [READ_BUF_SIZE]u8 align(8) = undefined;
    var fr = file.readerStreaming(io, &read_buf);
    var discard: std.Io.Writer.Discarding = .init(&.{});
    const enc = try encodeReader(&fr.interface, stat.size, &discard.writer);
    return enc.root;
}

/// Convenience: extract a verified range from a content file using its
/// outboard sidecar. Writes exactly `len` bytes into `out` (which must be
/// at least `len` bytes long). On verification failure returns the
/// underlying error (RootMismatch, SliceTruncated, …).
pub fn verifiedSeek(
    io: std.Io,
    alloc: std.mem.Allocator,
    outboard: *OutboardReader,
    content: std.Io.File,
    expected_root: Hash,
    offset: u64,
    len: u64,
    out: []u8,
) !void {
    std.debug.assert(out.len >= len);
    if (offset + len > outboard.content_length) return error.RangeOutOfFile;

    // Bound: 24-byte header + proof CVs along the path + chunk bytes for
    // every touched chunk. Upper bound: 24 + 32*depth*2 + chunk_length *
    // ceil(len/chunk_length) + 2*chunk_length (boundary slack).
    const chunk = blake3.chunk_length;
    const touched_chunks: u64 = if (len == 0) 0 else ((offset + len + chunk - 1) / chunk) - (offset / chunk);
    // Depth ≈ ceil(log2(n_chunks)) + 1. Use 64 to be safe (covers 2^64 chunks).
    const overhead: usize = 24 + 32 * 128;
    const slice_cap: usize = overhead + @as(usize, @intCast(touched_chunks)) * chunk;
    const slice_buf = try alloc.alloc(u8, slice_cap);
    defer alloc.free(slice_buf);

    var out_w = std.Io.Writer.fixed(slice_buf);
    try extractSliceFromOutboard(io, outboard, content, offset, len, &out_w);
    const slice_bytes = slice_buf[0..out_w.end];

    var in_r = std.Io.Reader.fixed(slice_bytes);
    _ = try verifySlice(&in_r, expected_root, out[0..len]);
}

// -----------------------------------------------------------------------------
// Streaming Verifier — the sync hot path.
//
// Peer A sends raw file content sequentially. Peer B has the matching on-disk
// outboard. Peer B feeds the incoming bytes through `Verifier.read`; bytes are
// only released to the caller after the chunk they belong to has been verified
// against the outboard's parent CVs (or, for the last chunk, against the
// expected root).
//
// Mirrors `encodeReader` byte-for-byte on the merge order, which is the same
// post-order in which the on-disk outboard stores parent CVs.
//
// Strict release rule: a chunk's bytes are released only after its CV has
// participated in at least one successful merge whose parent CV matched the
// outboard (or, for the last chunk, after the root matched `expected_root`).
//
// Buffer cost: by the popcount invariant, at any point at most ONE stack entry
// is a raw (not-yet-merged) chunk CV — always the top. So the verifier holds
// at most one chunk_length worth of "unverified pending" bytes (256 KiB),
// plus the chunk currently being filled (another 256 KiB), plus whatever is
// in the `released` queue awaiting drain. Bound: ~768 KiB.
// -----------------------------------------------------------------------------

pub const VerifierError = error{
    /// A parent CV computed from incoming content did not match the outboard.
    ContentMismatch,
    /// Final root CV did not match `expected_root`.
    RootMismatch,
    /// `content_in` returned EOF before the verifier had consumed
    /// `outboard.content_length` bytes.
    UnexpectedEof,
};

pub const Verifier = struct {
    io: std.Io,
    outboard: *OutboardReader,
    content_in: *std.Io.Reader,
    expected_root: Hash,
    bytes_remaining: u64,

    // Tree-merge state — mirrors encodeReader exactly.
    stack: [55][8]u32 = undefined,
    stack_len: usize = 0,
    /// Post-order cursor into the outboard's parent-CV table.
    outboard_cursor: u64 = 0,

    /// Counter for the chunk currently being filled from `content_in`.
    chunk_counter: u64 = 0,
    /// How many bytes of the current chunk have been pulled from `content_in`.
    cur_filled: usize = 0,
    cur_buf: [blake3.chunk_length]u8 = undefined,

    /// Bytes of the topmost-on-stack RAW chunk CV — i.e., a chunk whose CV
    /// has been pushed onto the stack but not yet merged. By the popcount
    /// invariant there is at most one such chunk at a time, always at the
    /// stack top. `pending_len == 0` means no such chunk is currently
    /// outstanding. Backed by `pending_buf`.
    pending_len: usize = 0,
    pending_buf: [blake3.chunk_length]u8 = undefined,

    /// Released chunks queue (FIFO) of verified bytes ready to drain into
    /// caller's dest. Two slots suffice: a single merge can verify the
    /// previously-pending chunk AND the just-pushed chunk simultaneously.
    released: [2][]u8 = .{ &.{}, &.{} },

    /// True once EOF + root verification have completed. After this, `.read`
    /// returns 0 once `released` drains.
    done: bool = false,
    /// Set on the empty-file path: nothing to read, just match the root.
    empty_root_checked: bool = false,

    pub fn init(
        io: std.Io,
        outboard: *OutboardReader,
        content_in: *std.Io.Reader,
        expected_root: Hash,
    ) Verifier {
        return .{
            .io = io,
            .outboard = outboard,
            .content_in = content_in,
            .expected_root = expected_root,
            .bytes_remaining = outboard.content_length,
        };
    }

    /// Drain up to `dest.len` verified bytes into `dest`. Returns 0 at EOF.
    /// On verification failure returns `error.ContentMismatch`,
    /// `error.RootMismatch`, or `error.UnexpectedEof`. Underlying I/O errors
    /// from `content_in` / `outboard` propagate.
    pub fn read(self: *Verifier, dest: []u8) !usize {
        // Empty file: no bytes flow, but root must still match.
        if (self.outboard.content_length == 0) {
            if (!self.empty_root_checked) {
                var expected: Hash = undefined;
                std.crypto.hash.Blake3.hash(&.{}, &expected, .{});
                if (!std.mem.eql(u8, &expected, &self.expected_root)) return error.RootMismatch;
                self.empty_root_checked = true;
                self.done = true;
            }
            return 0;
        }

        var written: usize = 0;
        while (written < dest.len) {
            // Drain any released bytes first.
            if (self.drainReleased(dest[written..])) |n| {
                written += n;
                continue;
            }
            if (self.done) break;
            try self.pump();
        }
        return written;
    }

    /// Copy from the `released` FIFO into `dest`. Returns null if both slots
    /// are empty, else the number of bytes copied (≥ 1).
    fn drainReleased(self: *Verifier, dest: []u8) ?usize {
        if (dest.len == 0) return null;
        for (&self.released) |*slot| {
            if (slot.*.len == 0) continue;
            const n = @min(slot.*.len, dest.len);
            @memcpy(dest[0..n], slot.*[0..n]);
            slot.* = slot.*[n..];
            return n;
        }
        return null;
    }

    /// Pull bytes from `content_in` into `cur_buf`. When a chunk closes (full
    /// or final), compute its CV and process via either intermediate or final
    /// path, which may populate `released`.
    fn pump(self: *Verifier) !void {
        const chunk = blake3.chunk_length;
        // This chunk's final length: chunk_length, unless it's the tail.
        const remaining_in_chunk_total: u64 = self.bytes_remaining + self.cur_filled;
        const this_chunk_len: usize = @intCast(@min(@as(u64, chunk), remaining_in_chunk_total));

        const want = this_chunk_len - self.cur_filled;
        if (want > 0) {
            const got = try self.content_in.readSliceShort(
                self.cur_buf[self.cur_filled..this_chunk_len],
            );
            if (got == 0) return error.UnexpectedEof;
            self.cur_filled += got;
            self.bytes_remaining -= got;
            if (self.cur_filled < this_chunk_len) return; // need more reads
        }

        // Chunk is full. Is it the last?
        if (self.bytes_remaining == 0) {
            try self.finaliseLastChunk(self.cur_buf[0..self.cur_filled]);
        } else {
            const bytes = self.cur_buf[0..self.cur_filled];
            const cv = blake3.chunkHash(bytes, self.chunk_counter, blake3.iv, .{});
            try self.processIntermediateChunk(bytes, cv);
        }
        self.cur_filled = 0;
    }

    /// Process a chunk that is known NOT to be the last. Push, merge,
    /// and release bytes from any chunks whose CVs participated in a verified
    /// merge.
    fn processIntermediateChunk(self: *Verifier, bytes: []u8, cv: [8]u32) !void {
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;

        const processed = self.chunk_counter + 1;
        const target_len: usize = @popCount(processed);

        // Track: did a merge happen that included the just-pushed chunk's CV?
        // If yes, both the previous pending (if any) and the current chunk
        // become verified-and-releasable.
        const will_merge = (self.stack_len > target_len);

        while (self.stack_len > target_len) {
            const left = self.stack[self.stack_len - 2];
            const right = self.stack[self.stack_len - 1];
            const parent = blake3.parentHash(left, right, blake3.iv, .{});
            self.stack[self.stack_len - 2] = parent;
            self.stack_len -= 1;

            const ob_cv_bytes = try self.outboard.cvAt(self.outboard_cursor);
            const parent_bytes = blake3.cvWordsToBytes(parent);
            if (!std.mem.eql(u8, &ob_cv_bytes, &parent_bytes)) return error.ContentMismatch;
            self.outboard_cursor += 1;
        }

        if (will_merge) {
            // Both the (possibly-empty) previous pending chunk and the
            // current chunk are now verified. Release pending first (older),
            // then current (newer), preserving file order.
            if (self.pending_len > 0) {
                self.released[0] = self.pending_buf[0..self.pending_len];
                self.released[1] = bytes;
                self.pending_len = 0;
            } else {
                self.released[0] = bytes;
                self.released[1] = &.{};
            }
        } else {
            // No merge: the just-pushed chunk is now the lone raw top. By
            // invariant, the previous pending must have been empty (a no-merge
            // push always follows a merge-bearing push or is the very first).
            std.debug.assert(self.pending_len == 0);
            @memcpy(self.pending_buf[0..bytes.len], bytes);
            self.pending_len = bytes.len;
        }

        self.chunk_counter += 1;
    }

    /// Finalise the last chunk. Single-chunk file: apply ROOT directly.
    /// Multi-chunk: hash last chunk without ROOT, climb stack with the ROOT
    /// flag on the final merge, comparing intermediate parents to the
    /// outboard and the root to `expected_root`. Release bytes (pending + last
    /// chunk) only after the root matches.
    fn finaliseLastChunk(self: *Verifier, bytes: []u8) !void {
        const total_chunks = self.chunk_counter + 1;

        if (total_chunks == 1) {
            std.debug.assert(self.pending_len == 0);
            const cv = blake3.chunkHash(
                bytes,
                0,
                blake3.iv,
                .{ .root = true },
            );
            const got = blake3.cvWordsToBytes(cv);
            if (!std.mem.eql(u8, &got, &self.expected_root)) return error.RootMismatch;
            self.released[0] = bytes;
            self.released[1] = &.{};
        } else {
            var current = blake3.chunkHash(
                bytes,
                self.chunk_counter,
                blake3.iv,
                .{},
            );
            while (self.stack_len > 0) {
                const left = self.stack[self.stack_len - 1];
                self.stack_len -= 1;
                const is_root_merge = (self.stack_len == 0);
                const parent = blake3.parentHash(
                    left,
                    current,
                    blake3.iv,
                    if (is_root_merge) .{ .root = true } else .{},
                );
                if (!is_root_merge) {
                    const ob_cv_bytes = try self.outboard.cvAt(self.outboard_cursor);
                    const parent_bytes = blake3.cvWordsToBytes(parent);
                    if (!std.mem.eql(u8, &ob_cv_bytes, &parent_bytes)) return error.ContentMismatch;
                    self.outboard_cursor += 1;
                }
                current = parent;
            }
            const got = blake3.cvWordsToBytes(current);
            if (!std.mem.eql(u8, &got, &self.expected_root)) return error.RootMismatch;

            // Root verified — release pending (if any) then last chunk.
            if (self.pending_len > 0) {
                self.released[0] = self.pending_buf[0..self.pending_len];
                self.released[1] = bytes;
                self.pending_len = 0;
            } else {
                self.released[0] = bytes;
                self.released[1] = &.{};
            }
        }

        self.done = true;
    }
};

// ---- tests ----

// ---------- tests ----------

const testing = std.testing;

test "encoder honors declared length and rejects short input" {
    const content = try testing.allocator.alloc(u8, (blake3.simd_degree + 1) * chunk_length + 17);
    defer testing.allocator.free(content);
    @memset(content, 0x5a);
    const sizes = [_]usize{ 1, chunk_length, chunk_length + 1, blake3.simd_degree * chunk_length + 1 };
    for (sizes) |size| {
        var short = std.Io.Reader.fixed(content[0 .. size - 1]);
        var discard: std.Io.Writer.Discarding = .init(&.{});
        try testing.expectError(error.UnexpectedEof, encodeReader(&short, size, &discard.writer));

        var extra = std.Io.Reader.fixed(content[0 .. size + 1]);
        var sink: std.Io.Writer.Discarding = .init(&.{});
        const result = try encodeReader(&extra, size, &sink.writer);
        try testing.expectEqual(size, result.content_length);
        try testing.expectEqual(@as(usize, 1), extra.bufferedLen());
        var tree = try buildTree(testing.allocator, content[0..size]);
        defer tree.deinit();
        try testing.expectEqualSlices(u8, &tree.root, &result.root);
    }
}

fn checkSize(alloc: std.mem.Allocator, content: []const u8) !void {
    var in = std.Io.Reader.fixed(content);
    // Outboard: 8 byte header + 32 * n_internal. Bound by n_chunks - 1.
    const max_out = 8 + 32 * (content.len / blake3.chunk_length + 2);
    const out_bytes = try alloc.alloc(u8, max_out);
    defer alloc.free(out_bytes);
    var out_w = std.Io.Writer.fixed(out_bytes);

    const enc = try encodeReader(&in, content.len, &out_w);

    // Cross-check streaming encoder vs in-memory tree builder.
    var tree = try buildTree(alloc, content);
    defer tree.deinit();
    try testing.expectEqualSlices(u8, &tree.root, &enc.root);

    try testing.expectEqual(@as(u64, content.len), enc.content_length);

    const expected_out_len: usize = 8 + 32 * @as(usize, @intCast(enc.n_internal));
    try testing.expectEqual(expected_out_len, out_w.end);
}

test "Bough encode/buildTree root agree across sizes" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{
        // Small / single-chunk boundary coverage.
        0,         1,       63,    64,        500,       1023,
        1024,      1025,    2048,  3072,      4096,      7000,
        100_000,   200_000,
        // Multi-chunk under 256 KiB regime.
        chunk, chunk + 1, 2 * chunk, 2 * chunk + 1,
        1_000_000,
        // SIMD batch boundaries (simd_degree may be 1 — duplicates harmless).
        blake3.simd_degree * chunk, // exactly one full vector batch
        blake3.simd_degree * chunk + 1, // batch + sub-chunk tail
        (blake3.simd_degree + 1) * chunk, // batch + one scalar-tail full chunk
        (2 * blake3.simd_degree + 3) * chunk + 12_345, // batches + scalar chunks + partial tail
    };
    for (sizes) |sz| {
        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i);
        try checkSize(testing.allocator, content);
    }
}

test "buildTree round-trips with encodeReader root" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{
        0,         1,             1024,      1025,    2048,  3072,
        4096,      7000,          100_000,   200_000, chunk, chunk + 1,
        2 * chunk, 2 * chunk + 1, 1_000_000,
    };
    for (sizes) |sz| {
        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i);

        var tree = try buildTree(testing.allocator, content);
        defer tree.deinit();

        var in = std.Io.Reader.fixed(content);
        const max_out = 8 + 32 * (sz / blake3.chunk_length + 2);
        const out_bytes = try testing.allocator.alloc(u8, max_out);
        defer testing.allocator.free(out_bytes);
        var out_w = std.Io.Writer.fixed(out_bytes);
        const enc = try encodeReader(&in, sz, &out_w);

        try testing.expectEqualSlices(u8, &enc.root, &tree.root);
    }
}

// ---- parallel subtree split/combine (issue #142) ----

/// In-memory oracle: encode `content` via the parallel path (subtreeSplit →
/// encodeSubtree×P → combineSubtrees) with an explicit segment size `C`.
/// Returns the file root + the combined outboard bytes (arena-owned).
fn oracleParallel(
    arena: std.mem.Allocator,
    content: []const u8,
    seg_chunks: u64,
) !struct { root: Hash, outboard: []u8 } {
    const n_chunks = chunksOf(content.len);
    const split: Split = .{
        .seg_chunks = if (n_chunks == 0) 0 else seg_chunks,
        .total_chunks = n_chunks,
    };
    const p = split.count();

    const roots = try arena.alloc([8]u32, @max(p, 1));
    const blobs = try arena.alloc([]const u8, @max(p, 1));

    var k: u64 = 0;
    while (k < p) : (k += 1) {
        const seg = split.segment(k);
        const blen = seg.byteLen(content.len);
        const bstart: usize = @intCast(seg.byteStart());
        var sin = std.Io.Reader.fixed(content[bstart..][0..@intCast(blen)]);
        const cap = 8 + 32 * (@as(usize, @intCast(seg.chunk_count)) + 1);
        const bbuf = try arena.alloc(u8, cap);
        var bw = std.Io.Writer.fixed(bbuf);
        roots[@intCast(k)] = try encodeSubtree(&sin, seg.startCounter(), blen, p == 1, &bw);
        blobs[@intCast(k)] = bbuf[0..bw.end];
    }

    const out_cap = 8 + 32 * (content.len / blake3.chunk_length + 2);
    const out_buf = try arena.alloc(u8, out_cap);
    var out_w = std.Io.Writer.fixed(out_buf);
    const root = try combineSubtrees(split, content.len, roots[0..p], blobs[0..p], &out_w);
    return .{ .root = root, .outboard = out_buf[0..out_w.end] };
}

test "parallel subtree encode is byte-identical to encodeReader" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{
        0,             1,             100,        chunk - 1,  chunk,               chunk + 1,
        2 * chunk,     3 * chunk,     4 * chunk,  5 * chunk,  7 * chunk,           8 * chunk,
        8 * chunk + 1, 8 * chunk - 1, 16 * chunk, 17 * chunk, 13 * chunk + 12_345,
    };
    // Segment sizes: C=1 reduces the combiner to encodeReader itself; larger
    // C exercises real subtree splices. C > n_chunks ⇒ P=1 (degenerate).
    const seg_cs = [_]u64{ 1, 2, 4, 8 };

    for (sizes) |sz| {
        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% (sz *% 7));

        const ref_buf = try testing.allocator.alloc(u8, 8 + 32 * (sz / chunk + 2));
        defer testing.allocator.free(ref_buf);
        var ref_w = std.Io.Writer.fixed(ref_buf);
        var ref_in = std.Io.Reader.fixed(content);
        const ref = try encodeReader(&ref_in, sz, &ref_w);
        const ref_ob = ref_buf[0..ref_w.end];

        for (seg_cs) |c| {
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            const got = try oracleParallel(arena.allocator(), content, c);
            testing.expectEqualSlices(u8, &ref.root, &got.root) catch |e| {
                std.debug.print("root mismatch sz={} C={}\n", .{ sz, c });
                return e;
            };
            testing.expectEqualSlices(u8, ref_ob, got.outboard) catch |e| {
                std.debug.print("outboard mismatch sz={} C={}\n", .{ sz, c });
                return e;
            };
        }
    }
}

test "positional parallel assembly is byte-identical to encodeReader" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{
        0,             1,             100,        chunk - 1,  chunk,               chunk + 1,
        2 * chunk,     3 * chunk,     4 * chunk,  5 * chunk,  7 * chunk,           8 * chunk,
        8 * chunk + 1, 8 * chunk - 1, 16 * chunk, 17 * chunk, 13 * chunk + 12_345,
    };
    const seg_cs = [_]u64{ 1, 2, 4, 8 };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    for (sizes) |sz| {
        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% (sz *% 11));

        const ref_buf = try testing.allocator.alloc(u8, 8 + 32 * (sz / chunk + 2));
        defer testing.allocator.free(ref_buf);
        var ref_w = std.Io.Writer.fixed(ref_buf);
        var ref_in = std.Io.Reader.fixed(content);
        const ref = try encodeReader(&ref_in, sz, &ref_w);
        const ref_ob = ref_buf[0..ref_w.end];

        for (seg_cs) |c| {
            var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const n_chunks = chunksOf(sz);
            const split: Split = .{
                .seg_chunks = if (n_chunks == 0) 0 else c,
                .total_chunks = n_chunks,
            };
            const p = split.count();

            var f = try tmp.dir.createFile(io, "pos.bao", .{ .read = true });
            defer f.close(io);

            // Each segment: collect its interior-CV run, then positional-write
            // it at segmentOutboardOffset(k). The offsets (and the final bytes)
            // are what's under test — not the streaming mechanics.
            const roots = try arena.alloc([8]u32, @max(p, 1));
            var k: u64 = 0;
            while (k < p) : (k += 1) {
                const seg = split.segment(k);
                const blen = seg.byteLen(sz);
                const bstart: usize = @intCast(seg.byteStart());
                var sin = std.Io.Reader.fixed(content[bstart..][0..@intCast(blen)]);
                const cap = 32 * (@as(usize, @intCast(seg.chunk_count)) + 1);
                const bbuf = try arena.alloc(u8, cap);
                var bw = std.Io.Writer.fixed(bbuf);
                roots[@intCast(k)] = try encodeSubtree(&sin, seg.startCounter(), blen, p == 1, &bw);
                try f.writePositionalAll(io, bbuf[0..bw.end], split.segmentOutboardOffset(k));
            }

            const root = try combineSubtreesPositional(split, sz, roots[0..p], io, f);
            testing.expectEqualSlices(u8, &ref.root, &root) catch |e| {
                std.debug.print("positional root mismatch sz={} C={}\n", .{ sz, c });
                return e;
            };

            const stat = try f.stat(io);
            try testing.expectEqual(@as(u64, ref_ob.len), stat.size);
            const got_ob = try arena.alloc(u8, ref_ob.len);
            const got_n = try f.readPositionalAll(io, got_ob, 0);
            try testing.expectEqual(ref_ob.len, got_n);
            testing.expectEqualSlices(u8, ref_ob, got_ob) catch |e| {
                std.debug.print("positional outboard mismatch sz={} C={}\n", .{ sz, c });
                return e;
            };
        }
    }
}

test "subtreeSplit: aligned segments, P in [target, 2·target)" {
    const target: u64 = 8;
    // n_chunks large enough that C is ratio-driven (ratio >= MIN_SEG_CHUNKS)
    // and P avoids the ceil boundary at exactly 2·target.
    const ns = [_]u64{ target * 4096, target * 4097, target * 6000, target * 7000, 100_000 };
    for (ns) |n| {
        const split = subtreeSplit(n, target);
        const p = split.count();
        try testing.expect(std.math.isPowerOfTwo(split.seg_chunks));
        try testing.expect(p >= target and p < 2 * target);

        var covered: u64 = 0;
        var k: u64 = 0;
        while (k < p) : (k += 1) {
            const seg = split.segment(k);
            try testing.expectEqual(covered, seg.start_chunk);
            if (k + 1 < p) {
                try testing.expectEqual(split.seg_chunks, seg.chunk_count);
            } else {
                try testing.expect(seg.chunk_count >= 1 and seg.chunk_count <= split.seg_chunks);
            }
            covered += seg.chunk_count;
        }
        try testing.expectEqual(n, covered);
    }
}

test "parallel-produced outboard reads back and verifies" {
    const sz: usize = 17 * blake3.chunk_length + 5000; // ragged, multi-segment at C=4
    const content = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 23);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const got = try oracleParallel(arena.allocator(), content, 4);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    {
        var f = try tmp.dir.createFile(io, "content.bin", .{});
        defer f.close(io);
        try f.writePositionalAll(io, content, 0);
    }
    {
        var f = try tmp.dir.createFile(io, "content.bao", .{});
        defer f.close(io);
        try f.writePositionalAll(io, got.outboard, 0);
    }

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();
    var cf = try tmp.dir.openFile(io, "content.bin", .{});
    defer cf.close(io);

    var tree = try buildTree(testing.allocator, content);
    defer tree.deinit();
    try testing.expectEqualSlices(u8, &tree.root, &got.root);

    var obc: u64 = 0;
    var tc: usize = 0;
    try walkCheckCvs(tree, &ob, &obc, &tc, 0, ob.n_chunks, true);
    try testing.expectEqual(ob.n_internal, obc);

    const out_buf = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(out_buf);
    const ranges = [_]struct { off: u64, len: u64 }{
        .{ .off = 0, .len = 100 },
        .{ .off = blake3.chunk_length * 3 - 10, .len = 5000 },
        .{ .off = sz - 64, .len = 64 },
    };
    for (ranges) |r| {
        try verifiedSeek(io, testing.allocator, &ob, cf, got.root, r.off, r.len, out_buf[0..r.len]);
        try testing.expectEqualSlices(u8, content[r.off..][0..r.len], out_buf[0..r.len]);
    }
}

test "extract+verify slice round-trips" {
    // ~1 MB = 4 chunks at 256 KiB — exercises multi-chunk slice paths.
    const content_len: usize = 1_000_000;
    const content = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 7);

    var tree = try buildTree(testing.allocator, content);
    defer tree.deinit();

    // Ranges crossing chunk boundaries (256 KiB = 262144).
    const ranges = [_]struct { off: u64, len: u64 }{
        .{ .off = 0, .len = 100 },
        .{ .off = 1000, .len = 100 },
        .{ .off = 200_000, .len = 200_000 }, // crosses chunk 0 → 1
        .{ .off = 262_143, .len = 2 }, // straddles chunk 0 / 1 boundary
        .{ .off = 500_000, .len = 300_000 }, // crosses chunk 1 → 2 → 3
        .{ .off = 0, .len = content_len }, // whole file
        .{ .off = content_len - 50, .len = 50 },
    };

    // Heap-allocate big buffers — stack allocation at this size is sketchy.
    const slice_buf = try testing.allocator.alloc(u8, 4 * content_len);
    defer testing.allocator.free(slice_buf);
    const range_buf = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(range_buf);

    for (ranges) |r| {
        var out_w = std.Io.Writer.fixed(slice_buf);
        try extractSlice(tree, content, r.off, r.len, &out_w);
        const slice_bytes = slice_buf[0..out_w.end];

        var in_r = std.Io.Reader.fixed(slice_bytes);
        const got_header = try verifySlice(&in_r, tree.root, range_buf[0..r.len]);

        try testing.expectEqual(@as(u64, content_len), got_header.content_length);
        try testing.expectEqual(r.off, got_header.offset);
        try testing.expectEqual(r.len, got_header.len);
        try testing.expectEqualSlices(u8, content[r.off..][0..r.len], range_buf[0..r.len]);
    }
}

test "verifySlice rejects wrong root" {
    // ~1 MB so verify actually traverses multiple chunks.
    const content_len: usize = 1_000_000;
    const content = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i);

    var tree = try buildTree(testing.allocator, content);
    defer tree.deinit();

    const slice_buf = try testing.allocator.alloc(u8, 2 * content_len);
    defer testing.allocator.free(slice_buf);
    var out_w = std.Io.Writer.fixed(slice_buf);
    try extractSlice(tree, content, 1000, 100, &out_w);

    var bogus_root: Hash = tree.root;
    bogus_root[0] ^= 1;

    var range_buf: [100]u8 = undefined;
    var in_r = std.Io.Reader.fixed(slice_buf[0..out_w.end]);
    try testing.expectError(error.RootMismatch, verifySlice(&in_r, bogus_root, &range_buf));
}

// ---- on-disk outboard / verified-seek tests ----

/// Helper: write `content` to `<dir>/content.bin` and its outboard to
/// `<dir>/content.bao`. Returns the encoded root.
fn writeTestFileAndOutboard(
    io: std.Io,
    dir: std.Io.Dir,
    content: []const u8,
) !Hash {
    {
        var f = try dir.createFile(io, "content.bin", .{});
        defer f.close(io);
        try f.writePositionalAll(io, content, 0);
    }
    var enc_root: Hash = undefined;
    {
        var f = try dir.createFile(io, "content.bao", .{});
        defer f.close(io);
        var w_buf: [64 * 1024]u8 = undefined;
        var fw = f.writerStreaming(io, &w_buf);
        const enc = try encodeFile(io, dir, "content.bin", &fw.interface);
        try fw.interface.flush();
        enc_root = enc.root;
    }
    return enc_root;
}

/// Pre-order DFS over the tree shape (excluding root, leaves), asserting
/// that OutboardReader returns the same CV the in-memory Tree holds at
/// the matching pre-order position. The cursor on OutboardReader walks
/// post-order; the Tree slot cursor walks pre-order — different orders,
/// but the SET of (subtree → CV) pairs must agree.
fn walkCheckCvs(
    tree: Tree,
    outboard: *OutboardReader,
    ob_cursor: *u64,
    tree_cursor: *usize,
    chunk_start: u64,
    chunk_count: u64,
    is_root: bool,
) !void {
    if (chunk_count <= 1) return;

    // Tree slot for this subtree (pre-order): non-root subtrees consume
    // one slot BEFORE descending.
    var my_tree_slot: ?usize = null;
    if (!is_root) {
        my_tree_slot = tree_cursor.*;
        tree_cursor.* += 1;
    }

    const left_chunks = leftSubtreeChunks(chunk_count);
    const right_chunks = chunk_count - left_chunks;
    const left_end = chunk_start + left_chunks;

    try walkCheckCvs(tree, outboard, ob_cursor, tree_cursor, chunk_start, left_chunks, false);
    try walkCheckCvs(tree, outboard, ob_cursor, tree_cursor, left_end, right_chunks, false);

    // After both children, the OutboardReader's slot for this subtree is
    // at ob_cursor (post-order). Verify it matches the tree's slot.
    if (!is_root) {
        const from_outboard = try outboard.cvAt(ob_cursor.*);
        const from_tree = tree.cvs[my_tree_slot.?];
        try testing.expectEqualSlices(u8, &from_tree, &from_outboard);
        ob_cursor.* += 1;
    }
}

test "OutboardReader.cvAt returns same CVs as in-memory Tree across sizes" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{
        chunk,
        chunk + 1,
        2 * chunk,
        5 * chunk,
        1_500_000,
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    for (sizes) |sz| {
        // Reset dir contents between iterations by deleting prior files.
        tmp.dir.deleteFile(io, "content.bin") catch {};
        tmp.dir.deleteFile(io, "content.bao") catch {};

        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% sz);

        const root = try writeTestFileAndOutboard(io, tmp.dir, content);

        var tree = try buildTree(testing.allocator, content);
        defer tree.deinit();
        try testing.expectEqualSlices(u8, &tree.root, &root);

        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        try testing.expectEqual(@as(u64, sz), ob.content_length);

        var ob_cursor: u64 = 0;
        var tree_cursor: usize = 0;
        try walkCheckCvs(tree, &ob, &ob_cursor, &tree_cursor, 0, ob.n_chunks, true);
        try testing.expectEqual(ob.n_internal, ob_cursor);
        try testing.expectEqual(tree.cvs.len, tree_cursor);
    }
}

test "OutboardReader rejects maximum, truncated, and oversized layouts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    {
        var file = try tmp.dir.createFile(io, "content.bao", .{});
        defer file.close(io);
        var header: [8]u8 = undefined;
        std.mem.writeInt(u64, &header, std.math.maxInt(u64), .little);
        try file.writePositionalAll(io, &header, 0);
    }
    try std.testing.expectError(error.OutboardTruncated, OutboardReader.open(io, tmp.dir, "content.bao"));

    {
        var file = try tmp.dir.createFile(io, "content.bao", .{ .truncate = true });
        defer file.close(io);
        var header: [8]u8 = undefined;
        std.mem.writeInt(u64, &header, 3 * blake3.chunk_length, .little);
        try file.writePositionalAll(io, &header, 0);
    }
    try std.testing.expectError(error.OutboardTruncated, OutboardReader.open(io, tmp.dir, "content.bao"));

    {
        var file = try tmp.dir.createFile(io, "content.bao", .{ .truncate = true });
        defer file.close(io);
        var bytes = [_]u8{0} ** 9;
        try file.writePositionalAll(io, &bytes, 0);
    }
    try std.testing.expectError(error.OutboardOversized, OutboardReader.open(io, tmp.dir, "content.bao"));
}

test "extractSliceFromOutboard round-trips with verifySlice" {
    const content_len: usize = 1_500_000;
    const content = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 13);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();
    var content_file = try tmp.dir.openFile(io, "content.bin", .{});
    defer content_file.close(io);

    const chunk = blake3.chunk_length;
    const ranges = [_]struct { off: u64, len: u64 }{
        .{ .off = 0, .len = 100 },
        .{ .off = 1234, .len = 4321 },
        .{ .off = chunk - 5, .len = 10 }, // crosses 0→1
        .{ .off = chunk * 2 - 1, .len = chunk + 2 }, // crosses 1→2→3
        .{ .off = 0, .len = content_len }, // whole file
        .{ .off = content_len - 99, .len = 99 }, // tail
        .{ .off = chunk * 3, .len = 1 }, // single chunk middle
    };

    const slice_buf = try testing.allocator.alloc(u8, 2 * content_len + 65_536);
    defer testing.allocator.free(slice_buf);
    const range_buf = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(range_buf);

    for (ranges) |r| {
        var out_w = std.Io.Writer.fixed(slice_buf);
        try extractSliceFromOutboard(io, &ob, content_file, r.off, r.len, &out_w);
        const slice_bytes = slice_buf[0..out_w.end];

        var in_r = std.Io.Reader.fixed(slice_bytes);
        const got_header = try verifySlice(&in_r, root, range_buf[0..r.len]);
        try testing.expectEqual(r.off, got_header.offset);
        try testing.expectEqual(r.len, got_header.len);
        try testing.expectEqualSlices(u8, content[r.off..][0..r.len], range_buf[0..r.len]);
    }
}

test "hashFile matches encodeReader root" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{ 0, 1, 1024, chunk, chunk + 1, 3 * chunk, 1_500_000 };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    for (sizes) |sz| {
        tmp.dir.deleteFile(io, "content.bin") catch {};

        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% (sz * 31));

        {
            var f = try tmp.dir.createFile(io, "content.bin", .{});
            defer f.close(io);
            if (sz != 0) try f.writePositionalAll(io, content, 0);
        }

        // Reference: encode in-memory.
        var in = std.Io.Reader.fixed(content);
        var discard: std.Io.Writer.Discarding = .init(&.{});
        const enc = try encodeReader(&in, sz, &discard.writer);

        // Under test: hashFile.
        const got = try hashFile(io, tmp.dir, "content.bin");
        try testing.expectEqualSlices(u8, &enc.root, &got);
    }
}

test "verifiedSeek returns correct verified bytes" {
    const content_len: usize = 1_500_000;
    const content = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 19);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();
    var content_file = try tmp.dir.openFile(io, "content.bin", .{});
    defer content_file.close(io);

    const ranges = [_]struct { off: u64, len: u64 }{
        .{ .off = 0, .len = 100 },
        .{ .off = blake3.chunk_length - 50, .len = 200 }, // boundary cross
        .{ .off = blake3.chunk_length * 2, .len = 1024 },
        .{ .off = content_len - 64, .len = 64 },
    };

    const out_buf = try testing.allocator.alloc(u8, content_len);
    defer testing.allocator.free(out_buf);

    for (ranges) |r| {
        try verifiedSeek(io, testing.allocator, &ob, content_file, root, r.off, r.len, out_buf[0..r.len]);
        try testing.expectEqualSlices(u8, content[r.off..][0..r.len], out_buf[0..r.len]);
    }

    // Bit-flip the content file and confirm verify fails.
    {
        // Flip a byte in chunk 2 region.
        const flip_offset: u64 = blake3.chunk_length * 2 + 7;
        var byte_buf: [1]u8 = undefined;
        const got = try content_file.readPositionalAll(io, &byte_buf, flip_offset);
        try testing.expectEqual(@as(usize, 1), got);
        byte_buf[0] ^= 0xff;

        // Re-open writable to flip.
        var wf = try tmp.dir.openFile(io, "content.bin", .{ .mode = .read_write });
        defer wf.close(io);
        try wf.writePositionalAll(io, &byte_buf, flip_offset);
    }

    // Verified seek into the corrupted region must fail.
    const bad_off: u64 = blake3.chunk_length * 2;
    const bad_len: u64 = 1024;
    try testing.expectError(
        error.RootMismatch,
        verifiedSeek(io, testing.allocator, &ob, content_file, root, bad_off, bad_len, out_buf[0..bad_len]),
    );
}

// ---- streaming Verifier tests ----

/// An unbuffered transport that fragments reads and can fail at a byte offset.
const VerifierTestReader = struct {
    reader: std.Io.Reader = .{
        .vtable = &.{ .stream = stream },
        .buffer = &.{},
        .seek = 0,
        .end = 0,
    },
    content: []const u8,
    position: usize = 0,
    fragment: usize = 4093,
    fail_at: ?usize = null,

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *@This() = @fieldParentPtr("reader", r);
        if (self.fail_at) |offset| {
            if (self.position >= offset) return error.ReadFailed;
        }
        if (self.position == self.content.len) return error.EndOfStream;
        const end = @min(self.content.len, self.fail_at orelse self.content.len);
        const n = try w.write(limit.sliceConst(self.content[self.position..@min(end, self.position + self.fragment)]));
        self.position += n;
        return n;
    }
};

test "Verifier batch boundaries, fragmented input and repeated drains" {
    const sizes = [_]usize{
        0,                      1,                 chunk_length - 1,  chunk_length,          chunk_length + 1,
        2 * chunk_length,       7 * chunk_length,  8 * chunk_length,  8 * chunk_length + 1,  9 * chunk_length,
        9 * chunk_length + 17,  15 * chunk_length, 16 * chunk_length, 16 * chunk_length + 1, 17 * chunk_length,
        17 * chunk_length + 63,
    };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const content = try testing.allocator.alloc(u8, sizes[sizes.len - 1] + 1);
    defer testing.allocator.free(content);
    var random = std.Random.DefaultPrng.init(0x9b035eed);
    random.random().bytes(content);
    const dest = try testing.allocator.alloc(u8, chunk_length + 7);
    defer testing.allocator.free(dest);
    const v = try testing.allocator.create(Verifier);
    defer testing.allocator.destroy(v);
    for (sizes) |size| {
        const root = try writeTestFileAndOutboard(io, tmp.dir, content[0..size]);
        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        // The extra byte belongs to the next message, not this file.
        var source: VerifierTestReader = .{ .content = content[0 .. size + 1] };
        v.* = Verifier.init(io, &ob, &source.reader, root);
        var position: usize = 0;
        var iteration: usize = 0;
        const drains = [_]usize{ 1, 17, 65536, chunk_length + 7 };
        while (true) : (iteration += 1) {
            const n = try v.read(dest[0..drains[iteration % drains.len]]);
            if (n == 0) break;
            try testing.expect(position + n <= size);
            try testing.expectEqualSlices(u8, content[position..][0..n], dest[0..n]);
            position += n;
        }
        try testing.expectEqual(size, position);
        try testing.expectEqual(size, source.position);
        try testing.expectEqual(@as(usize, 0), try v.read(dest));
    }
}

test "Verifier never releases corrupt chunks across batches or final root" {
    const size = 17 * chunk_length + 31;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const content = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(content);
    var random = std.Random.DefaultPrng.init(0xa71b);
    random.random().bytes(content);
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);
    const v = try testing.allocator.create(Verifier);
    defer testing.allocator.destroy(v);
    // Every lane of both full batches, the pending chunk and the final tail.
    for (0..18) |chunk_index| {
        const offset = chunk_index * chunk_length;
        content[offset] ^= 1;
        defer content[offset] ^= 1;
        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        var source = std.Io.Reader.fixed(content);
        v.* = Verifier.init(io, &ob, &source, root);
        var dest: [4093]u8 = undefined;
        var position: usize = 0;
        while (true) {
            const n = v.read(&dest) catch |err| {
                // Even the final pair has a non-root parent in this tree.
                try testing.expectEqual(error.ContentMismatch, err);
                break;
            };
            try testing.expect(n > 0);
            position += n;
            // A pair is released together only after its parent matches.
            try testing.expect(position <= (chunk_index / 2) * 2 * chunk_length);
            try testing.expectEqualSlices(u8, content[position - n .. position], dest[0..n]);
        }
    }
}

test "Verifier proof failures, truncation and transport errors around batches" {
    const size = 17 * chunk_length + 31;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const content = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(content);
    var random = std.Random.DefaultPrng.init(0xefface);
    random.random().bytes(content);
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);
    const v = try testing.allocator.create(Verifier);
    defer testing.allocator.destroy(v);
    const out = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(out);
    const cuts = [_]usize{ 0, 1, 2 * chunk_length, 8 * chunk_length - 1, 8 * chunk_length, 16 * chunk_length + 1, size - 1 };
    for (cuts) |cut| {
        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        var short: VerifierTestReader = .{ .content = content[0..cut] };
        v.* = Verifier.init(io, &ob, &short.reader, root);
        try testing.expectError(error.UnexpectedEof, drainVerifier(v, out));
        var failed: VerifierTestReader = .{ .content = content, .fail_at = cut };
        v.* = Verifier.init(io, &ob, &failed.reader, root);
        try testing.expectError(error.ReadFailed, drainVerifier(v, out));
    }
    const proof = try tmp.dir.openFile(io, "content.bao", .{ .mode = .read_write });
    defer proof.close(io);
    for ([_]u64{ 0, 6, 14, 15 }) |index| {
        var original: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try proof.readPositionalAll(io, &original, 8 + index * 32));
        try proof.writePositionalAll(io, &.{original[0] ^ 1}, 8 + index * 32);
        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        var source = std.Io.Reader.fixed(content);
        v.* = Verifier.init(io, &ob, &source, root);
        try testing.expectError(error.ContentMismatch, drainVerifier(v, out));
        try proof.writePositionalAll(io, &original, 8 + index * 32);
    }
    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();
    var wrong_root = root;
    wrong_root[0] ^= 1;
    var source = std.Io.Reader.fixed(content);
    v.* = Verifier.init(io, &ob, &source, wrong_root);
    try testing.expectError(error.RootMismatch, drainVerifier(v, out));
    try proof.setLength(io, 8);
    source = .fixed(content);
    v.* = Verifier.init(io, &ob, &source, root);
    try testing.expectError(error.OutboardTruncated, drainVerifier(v, out));
}

/// Drive a Verifier to EOF, accumulating its output into `out_bytes` (which
/// must be sized to the expected content length). Returns the total bytes
/// emitted. Pulls into a small 1 KiB dest buffer to exercise multiple reads.
fn drainVerifier(v: *Verifier, out_bytes: []u8) !usize {
    var written: usize = 0;
    var tmp_buf: [1024]u8 = undefined;
    while (true) {
        const n = try v.read(&tmp_buf);
        if (n == 0) break;
        @memcpy(out_bytes[written..][0..n], tmp_buf[0..n]);
        written += n;
    }
    return written;
}

test "Verifier streams correct content for sizes 0 / 1 / 1 chunk / chunk+1 / 5 chunks / 1_500_000" {
    const chunk = blake3.chunk_length;
    const sizes = [_]usize{ 0, 1, chunk, chunk + 1, 5 * chunk, 1_500_000 };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    for (sizes) |sz| {
        tmp.dir.deleteFile(io, "content.bin") catch {};
        tmp.dir.deleteFile(io, "content.bao") catch {};

        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% (sz * 91));

        const root = try writeTestFileAndOutboard(io, tmp.dir, content);

        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();

        const out_bytes = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(out_bytes);

        var content_reader = std.Io.Reader.fixed(content);
        var v = Verifier.init(io, &ob, &content_reader, root);
        const n = try drainVerifier(&v, out_bytes);
        try testing.expectEqual(sz, n);
        try testing.expectEqualSlices(u8, content, out_bytes);
    }
}

test "Verifier rejects flipped content byte" {
    // Use a 5-chunk file so a flip in the middle gets caught by a parent CV
    // mismatch BEFORE the final root check (i.e. ContentMismatch, not
    // RootMismatch).
    const sz: usize = 5 * blake3.chunk_length;
    const content = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 71);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();

    // Flip a byte inside chunk 1 (so the merge p01 catches it).
    const flipped = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(flipped);
    @memcpy(flipped, content);
    flipped[blake3.chunk_length + 100] ^= 0x80;

    const out_bytes = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(out_bytes);

    var content_reader = std.Io.Reader.fixed(flipped);
    var v = Verifier.init(io, &ob, &content_reader, root);
    try testing.expectError(error.ContentMismatch, drainVerifier(&v, out_bytes));
}

test "Verifier rejects wrong expected_root" {
    // Single-chunk file: no parent merges, so only the root check can fire.
    const sz: usize = 1024;
    const content = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();

    var bogus_root: Hash = root;
    bogus_root[5] ^= 0xff;

    const out_bytes = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(out_bytes);

    var content_reader = std.Io.Reader.fixed(content);
    var v = Verifier.init(io, &ob, &content_reader, bogus_root);
    try testing.expectError(error.RootMismatch, drainVerifier(&v, out_bytes));
}

test "Verifier rejects truncated content" {
    const sz: usize = 3 * blake3.chunk_length;
    const content = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i +% 11);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();

    // Provide ONLY 1.5 chunks of content — fewer bytes than the outboard
    // says exist.
    const truncated_len: usize = blake3.chunk_length + blake3.chunk_length / 2;
    const out_bytes = try testing.allocator.alloc(u8, sz);
    defer testing.allocator.free(out_bytes);

    var content_reader = std.Io.Reader.fixed(content[0..truncated_len]);
    var v = Verifier.init(io, &ob, &content_reader, root);
    try testing.expectError(error.UnexpectedEof, drainVerifier(&v, out_bytes));
}

test "Verifier handles single-chunk file" {
    // Edge: a single chunk's worth of content (and slightly under). No
    // outboard CVs are consumed; the root is the chunk's CV with ROOT flag.
    const sizes = [_]usize{ 1, 1024, blake3.chunk_length };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    for (sizes) |sz| {
        tmp.dir.deleteFile(io, "content.bin") catch {};
        tmp.dir.deleteFile(io, "content.bao") catch {};

        const content = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(content);
        for (content, 0..) |*b, i| b.* = @truncate(i +% (sz * 3));

        const root = try writeTestFileAndOutboard(io, tmp.dir, content);

        var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
        defer ob.close();
        try testing.expectEqual(@as(u64, 0), ob.n_internal);

        const out_bytes = try testing.allocator.alloc(u8, sz);
        defer testing.allocator.free(out_bytes);

        var content_reader = std.Io.Reader.fixed(content);
        var v = Verifier.init(io, &ob, &content_reader, root);
        const n = try drainVerifier(&v, out_bytes);
        try testing.expectEqual(sz, n);
        try testing.expectEqualSlices(u8, content, out_bytes);
    }
}

test "Verifier handles empty file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    const content: []const u8 = &.{};
    const root = try writeTestFileAndOutboard(io, tmp.dir, content);

    var ob = try OutboardReader.open(io, tmp.dir, "content.bao");
    defer ob.close();
    try testing.expectEqual(@as(u64, 0), ob.content_length);
    try testing.expectEqual(@as(u64, 0), ob.n_internal);

    var content_reader = std.Io.Reader.fixed(content);
    var v = Verifier.init(io, &ob, &content_reader, root);

    // First read should return 0 (EOF) after verifying the empty-file root.
    var dest: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try v.read(&dest));

    // Subsequent reads stay at 0.
    try testing.expectEqual(@as(usize, 0), try v.read(&dest));

    // Wrong root must fail on empty too.
    var bogus: Hash = root;
    bogus[0] ^= 1;
    var v2 = Verifier.init(io, &ob, &content_reader, bogus);
    try testing.expectError(error.RootMismatch, v2.read(&dest));
}
