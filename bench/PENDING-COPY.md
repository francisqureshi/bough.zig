# Pending-chunk borrowing experiment — 14 November 2026

The streaming verifier can borrow an unmerged chunk from its batch when the
successor is already in that batch. The next merge checks the pair, and read()
drains released slices before another pump/refill. Scalar tails still copy to
owned pending storage. A refill assertion rejects outstanding borrowed storage.
Proof/root comparisons, release order and the copy into caller storage remain.

```text
pending chunk + successor already in batch
  → retain offset, verify pair, drain both, then permit refill
pending chunk without successor in batch
  → copy into owned pending storage before refill
```

## Initial local evidence

HWS Ryzen 7 5800X, CPU 2 affinity, native AVX2, x86_64_v3+aes+pclmul,
Zig 0.17 safe static musl. The app's pinned Bough 28306c4 is the baseline;
the candidate differs only in pending-byte storage. Main's Zig 0.16 verifier
is identical apart from an unrelated test array initializer.

Five alternating runs A/B/A/B/A, each three rounds per mode and 4 GiB per round.
32 MiB memory-backed input, 256 KiB output, cached outboard. Pooled medians:

| Component | Baseline Gbit/s | Candidate Gbit/s | Change |
| --- | ---: | ---: | ---: |
| Verify | 23.854 | 24.718 | +3.62% |
| Serial decrypt/verify/copy | 11.459 | 11.668 | +1.83% |

Both variants passed all 34 native safe tests; the candidate also passed all
34 scalar Debug tests. An intentionally broken control borrowed across refills
and disabled the refill assertion: two existing byte/release tests failed.
Existing coverage includes fragmented input, tiny drains, chunk/batch boundaries,
corrupt content/proofs, wrong roots, truncation and read failures. Benchmark
negative controls reject bad AEAD tags, corrupted content and wrong roots.

This is a component experiment, not real TLS, network, publication or NAS sync
qualification. The full-buffer serial combined probe has different cache/copy
behaviour from the streaming daemon. No integrity check was removed.

Raw logs, binaries, complete sources, patch and reproduction script:
`/home/fq/Projects/Zig/h-rplca/demos/nas-sync-test/public-performance/bough-copy-experiment-20261114/`.
The standalone harness is h-rplca PR #381 (`fe3055a`),
`tools/benchmarks/receive-pipeline` with a local Bough dependency override.
