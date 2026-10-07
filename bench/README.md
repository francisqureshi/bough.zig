# Large-file benchmarks

## Results on this machine

These are the **pre-optimization** results. See [SCALING.md](SCALING.md) for the
new native backend, parallel encoding, and full-load experiments. Also see the
[25 GB single-core rematch](RACE-25GB.md), which includes measured cache residency.
These historical results predate the rename to bough.zig; hashes and the outboard
format are unchanged.

10 GiB (10,737,418,240 bytes), AMD Ryzen 7 5800X, Linux, 32 GiB RAM,
one process pinned to logical CPU 2. Three runs per case; medians below.
Input was a dense file made from an 8 MiB random block repeated 1,280 times.
No compression is performed by either implementation.

Zig 0.16.0, `ReleaseFast`, native CPU target; Rust 1.95.0, release,
`target-cpu=native`; Bao 0.13.1 and BLAKE3 1.8.7 (Cargo.lock included).
Library revision: `a3da1e13836dd9d599018cf3d857cc59e3942066`.
Neither driver uses multithreading or mmap. Timings include process startup,
reading input, hashing, finalization, and flushing output, but not `fsync`.

| Warm-cache operation | Seconds | GiB/s |
| --- | ---: | ---: |
| Zig `hashFile` | 3.640 | 2.747 |
| Rust BLAKE3 hash | 2.818 | 3.549 |
| Zig outboard, file-backed | 3.651 | 2.739 |
| Rust Bao outboard, file-backed | 50.910 | 0.196 |
| Rust Bao outboard, memory-backed then written to file | 15.988 | 0.625 |

Hash-only with input page-cache eviction requested before each run:

| Implementation | Seconds | GiB/s |
| --- | ---: | ---: |
| Zig | 9.621 | 1.039 |
| Rust BLAKE3 | 8.067 | 1.240 |

Eviction uses Linux `POSIX_FADV_DONTNEED`: it is a hint, not proof of cold
physical storage, and does not flush drive caches. Warm input is explicitly read
before each timed run. Implementation order alternates across repetitions.
The machine was not otherwise reserved, and CPU clocks were not fixed by us.

A separate warm-cache Zig baseline-CPU build took 6.865 s (1.457 GiB/s), versus
3.640 s with the native target. Both modules must receive the compiler flags.

### Interpretation

- Rust BLAKE3 delivers about **29% higher hash-only throughput** here. This does
  not establish the fastest implementation of Zig's custom hash construction.
- Zig outboards are **1,310,664 bytes (~1.25 MiB)**, versus Rust Bao's
  **671,088,584 bytes (~640 MiB)**: about 512 times smaller. The algorithms do
  different work: Zig uses 256 KiB hashing chunks and stores non-root internal
  CVs; canonical Bao uses 1 KiB chunks and child-CV pairs in pre-order.
- Rust Bao's file-backed incremental encoder performs a seek/read/write-heavy
  post-order-to-pre-order pass. It used about 28 s of system CPU time per run.
  Keeping the sidecar in a `Cursor<Vec<u8>>` eliminates those file seeks but
  uses ~640 MiB of extra memory. It is much faster, yet still slower than this
  Zig implementation. These are specific encoder-path comparisons, not a
  blanket Rust-versus-Zig performance claim.
- Page-cache eviction makes storage costs substantial. Multicore hashing,
  mmap, verification speed, and other Bao implementations were not benchmarked.

Hash and outboard modes returned identical roots within each implementation
across all runs. Rust's memory/file-backed outboards were byte-identical (`cmp`).
Zig and Rust roots differ, as expected for these different hash constructions.
`zig build test -Doptimize=ReleaseFast` passed.

Raw measurements are in [`results/`](results/). Early calibration runs are not
included in the tables.

## Reproduce

The Zig driver measures `Bough.hashFile` or `Bough.encodeFile` including file I/O.
The current build system configures both modules and the backend options, from
the repository root (current source includes the no-copy optimization; use the
recorded original revision to reproduce the historical implementation):

```sh
zig build bench -Doptimize=ReleaseFast -Dcpu=native -Dnative-kernel=false
cp zig-out/bin/bough-bench /tmp/zig-bough-bench

CARGO_TARGET_DIR=/tmp/bao-rust-target RUSTFLAGS='-C target-cpu=native' \
  cargo build --release --locked --manifest-path bench/rust/Cargo.toml
```

Rust tooling was provided here by `nix shell nixpkgs#cargo nixpkgs#rustc
nixpkgs#gcc`. Use a dedicated work directory and a dense 10 GiB input file.
For example, create one without allocating 10 GiB of RAM:

```sh
mkdir -p /tmp/bao-benchmark
python3 - <<'PY'
import os
block = os.urandom(8 * 1024 * 1024)
with open('/tmp/bao-benchmark/input.bin', 'xb') as f:
    for _ in range(1280):
        f.write(block)
    f.flush()
    os.fsync(f.fileno())
PY

BENCH_CPU=2 python3 bench/run.py /tmp/zig-bough-bench \
  /tmp/bao-rust-target/release/bao-rust-bench \
  /tmp/bao-benchmark/input.bin /tmp/bao-benchmark/warm 3
```

The runner overwrites sidecars and `results.json` in its work directory.
Choose a CPU allowed by your machine's affinity mask. Additional cases:

- `BENCH_CACHE=evict BENCH_MODES=hash`: input eviction before hash-only runs.
- `BENCH_IMPLS=rust BENCH_MODES=outboard-memory`: memory-backed Rust outboard.
- For the Zig baseline case, use `-Dcpu=baseline`; the standalone driver accepts `hash INPUT` or
  `outboard INPUT OUTPUT`.

The Rust hash mode measures the underlying BLAKE3 crate, not Bao encoding.
The default outboard mode buffers file output but forwards seeks and reads to
the file, so the final tree-reordering pass remains file-backed. The memory mode
still streams the input; only the sidecar is retained in RAM before writing it.

## Streaming verifier acceleration (2026-10-07)

Measured on hws, Ryzen 7 5800X, Zig 0.16.0, ReleaseFast, native CPU target.
The baseline is `3f06b536`; the batched implementation is `c20b5fb`.
Three repetitions alternated implementation order, with compilation completed
before timing. These are local measurements, not production NAS capacity tests.

The resident-input benchmark verifies a 128 MiB random fixture 16 times per
sample, pinned to logical CPU 0, with file-backed warm outboards and a 64 KiB
output buffer. Fixture creation and input loading are outside both elapsed and
process-CPU timing. Proof reads, hashing, verifier initialization and copying
verified output into the discard buffer are included.

| Verifier | Median GB/s (range) | CPU seconds/GiB | First read, ms | Object bytes |
| --- | ---: | ---: | ---: | ---: |
| Original scalar | 0.730 (0.730–0.730) | 1.466 | 0.951 | 526,200 |
| Portable Zig batching | 3.208 (3.125–3.225) | 0.334 | 1.776 | 2,361,472 |
| Native AVX2 batching | 3.882 (3.865–3.902) | 0.276 | 1.533 | 2,361,472 |

Native batching delivered **5.32× throughput and 81.2% lower CPU cost** in
this benchmark. Its object contains 2.25 MiB of payload storage and 2,176 bytes
of metadata. First-read latency includes touching fresh verifier storage and
filling a batch; it increased despite better steady-state throughput. Smaller
files and incomplete SIMD groups retain chunk-at-a-time reads.

A separate hash-kernel comparison (no proofs or output copies) measured
0.801 GB/s scalar versus 5.461 GB/s native, or 6.82×. This isolates compression
work and should not be substituted for end-to-end receiver throughput.

The existing INFRA-518 harness was rebuilt with a local Bough override. It uses
one-executor Zio processes, native loopback sendfile, warm 128 MiB transfer
fixtures and 64 KiB receiver buffers. The following are medians of three runs;
receive CPU includes process startup and all receiver work.

| Workload, output writes disabled | Original Gb/s | Batched Gb/s | Original receive CPU s/GiB | Batched receive CPU s/GiB |
| --- | ---: | ---: | ---: | ---: |
| One lane, 2 GiB/sample | 4.87 | 21.36 | 1.687 | 0.353 |
| Four lanes, 4 GiB/sample | 18.96 | 75.19 | 1.717 | 0.398 |
| One lane + one background hash worker, 2 GiB/sample | 4.83 | 21.30 | 1.698 | 0.353 |

In the mixed case the worker encoded a warm 64 MiB fixture and synced its
outboard; completed background hashing was 3.29 GB/s with the original verifier
and 3.20 GB/s with the batched verifier. Whole completed jobs within the receive
interval are counted, so the shorter batched samples have more boundary bias.
Peak sampled receiver RSS was approximately 3.81 MiB original and 5.56 MiB
batched, excluding filesystem cache. RSS sampling was every 50 ms.

A limited durable comparison wrote 1 GiB per implementation, syncing each
128 MiB file: 3.22 Gb/s original (2.67 seconds) versus 6.71 Gb/s batched
(1.28 seconds). Final outputs matched independent SHA-256. These single, short,
sequential samples do not establish sustained disk throughput. They include
file sync but not directory sync, publication or production protocol overhead.

All 32 library tests passed with native and portable ReleaseFast builds, native
Debug, and portable Debug with a baseline CPU target. The portable benchmark
also cross-compiled for aarch64 Linux. The Zio harness accepted valid data and
rejected corrupt content, truncation and wrong roots; the consumer application
built with the local dependency override.

To run the resident benchmark on a prepared input:

```sh
zig build bench -Doptimize=ReleaseFast -Dcpu=native -Dnative-kernel=true
# Prints the expected root in hexadecimal:
zig-out/bin/bough-bench outboard INPUT OUTBOARD
# Supply that root as ROOT_HEX; emits JSON timing and verifier size:
zig-out/bin/bough-bench verify INPUT OUTBOARD ROOT_HEX 16
```

Use `-Dnative-kernel=false` for the portable batched implementation; it is not
the original scalar verifier. Build the same benchmark driver against
`3f06b536` for a scalar-verifier comparison. Scratch sources, exact commands,
raw measurements, binary hashes and cleanup details are retained locally in
the ignored `.local-evidence/verifier-2026-10-07/` directory.
