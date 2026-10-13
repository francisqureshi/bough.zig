//! Resumable root-only hashing over caller-owned whole chunks. No payload is
//! retained: callers can release each batch after update and move this value
//! between workers after joining the previous owner. Uses the same tree shape,
//! counters and SIMD kernel as encodeReader; does not emit an outboard.
const std = @import("std");
const blake3 = @import("blake3_lo.zig");

const Self = @This();
size: u64,
consumed: u64 = 0,
stack: [55][8]u32 = undefined,
stack_len: usize = 0,
root: [32]u8 = undefined,

pub fn init(size: u64) Self {
    return .{ .size = size };
}

/// Non-final updates must contain whole Bough chunks. The last update may end
/// in a short chunk. Invalid lengths leave the hasher unchanged.
pub fn update(self: *Self, bytes: []const u8) error{InvalidLength}!void {
    const remaining = self.size - self.consumed;
    if (bytes.len == 0 or bytes.len > remaining or
        (bytes.len < remaining and bytes.len % blake3.chunk_length != 0))
    {
        return error.InvalidLength;
    }
    var input = bytes;
    while (input.len > 0) {
        const counter = self.consumed / blake3.chunk_length;
        const nonfinal = (self.size - self.consumed - 1) / blake3.chunk_length;
        if (nonfinal > 0) {
            const count: usize = @intCast(@min(
                blake3.simd_degree,
                nonfinal,
                input.len / blake3.chunk_length,
            ));
            std.debug.assert(count > 0);
            const len = count * blake3.chunk_length;
            var hashes: [blake3.simd_degree][8]u32 = undefined;
            blake3.hashManyContiguous(input[0..len], counter, blake3.iv, hashes[0..count]);
            for (hashes[0..count], 0..) |hash, i| {
                self.stack[self.stack_len] = hash;
                self.stack_len += 1;
                const target: usize = @popCount(counter + i + 1);
                while (self.stack_len > target) {
                    self.stack[self.stack_len - 2] = blake3.parentHash(
                        self.stack[self.stack_len - 2],
                        self.stack[self.stack_len - 1],
                        blake3.iv,
                        .{},
                    );
                    self.stack_len -= 1;
                }
            }
            self.consumed += len;
            input = input[len..];
        } else {
            var current = blake3.chunkHash(input, counter, blake3.iv, .{
                .root = self.stack_len == 0,
            });
            while (self.stack_len > 0) {
                self.stack_len -= 1;
                current = blake3.parentHash(
                    self.stack[self.stack_len],
                    current,
                    blake3.iv,
                    .{ .root = self.stack_len == 0 },
                );
            }
            self.root = blake3.cvWordsToBytes(current);
            self.consumed += input.len;
            input = &.{};
        }
    }
}

pub fn finish(self: *const Self) error{IncompleteContent}![32]u8 {
    if (self.consumed != self.size) return error.IncompleteContent;
    if (self.size == 0) {
        var root: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&.{}, &root, .{});
        return root;
    }
    return self.root;
}
