# Design and performance

## Language and compatibility

Keep JavaScript on Node as the reference implementation. The archive reader, CLI, and compatibility suite run with Node's built-in filesystem, crypto, and zlib modules. Regrow-8 can use the same implementation. The existing C predictor is an optional WebAssembly backend for long-window recipes. It emits the same bytes as the JavaScript predictor on the benchmark and compatibility tests.

This extract keeps the GRP1 frame layout, both parity profiles, and the existing GRF1 and GRL encoding rules. GF16 now accumulates directly into 16-bit output words on little-endian hosts and retains byte-wise arithmetic on big-endian hosts. The GRF1 row-rule fitter also reuses adjacent bits when counting neighborhoods. These changes preserve the same parity and recipe bytes. [GF16 kernel](../src/rs16.mjs) · [GRF1 codec](../src/codec.mjs)

## Measurements

The benchmark used Node 22.16.0 on Windows x64 with an Intel Core i7-14700. Each time is the median of three runs. The baseline is the Automaton Swarm codec at commit `1f458b7`. The benchmark generates its own inputs. The binary and text runs used 5% global parity and recovered one physically deleted data frame. They verify the original and regenerated archive after timing.

| Measurement | Swarm baseline | Standalone | Protected bytes |
| --- | ---: | ---: | ---: |
| GF16 encode, 384 shards of up to 88 KiB and 20 parity rows | 444.1 ms | 404.3 ms | Same parity bytes |
| Pack about 2 MiB of seeded binary data with text modes off | 240.9 ms | 235.7 ms | 2,365,892 |
| Recover that binary archive | 34.3 ms | 30.9 ms | 2,365,892 |
| Pack 1 MiB of structured text with the default GRF1 settings | 411.3 ms | 381.7 ms | 62,991 |
| Recover that text archive | 92.9 ms | 96.4 ms | 62,991 |

The kernel change saved about 9% on the isolated GF16 encode. Both same-settings archives matched the baseline SHA-256. Small end-to-end differences include CPU and filesystem variation. The default text recovery median was slightly slower in this run.

- With text and templates off, the 1 MiB text archive packed in **80.0 ms** and recovered in **12.3 ms**. It grew from 62,991 to 90,304 bytes. This input favors the faster profile when the extra 43% of storage is acceptable.
- The optional C/Wasm predictor packed the same text as a GRL2 recipe in **57.5 ms** versus **97.6 ms** for JavaScript with a single job. The two GRL2 files matched byte for byte. This measures the long-window predictor path, separate from GRF1 and parity.

Reproduce with `npm run benchmark -- ../automaton-swarm/examples/file_recipe`. Set `GRL_PREDICTOR_WASM` to a locally built module to include the predictor comparison. Run the benchmark by itself to reduce timing interference. [Benchmark source](../benchmarks/run.mjs)

## Where further work can help

1. **Parallelize GRF1 group encoding.** Each 256 KiB group can be encoded and checked independently. Measure a bounded worker pool that retains group order. A profile of the binary workload showed time spread across DEFLATE, stride and rule selection, and parity. Start with the group-level work before specializing the individual search passes.
2. **Add an original-only recovery operation.** The current recovery operation stages the original, the inner recipe, and the complete protected archive. An operation for callers who need only the original could skip regenerating every parity row after verifying the original digest.
3. **Benchmark native parity on larger archives.** Global parity combines each systematic shard with each parity row, and the 8 MiB output batching can reread inputs for later batches. Measure compute and file reads separately on large archives with large parity budgets. A native or Wasm kernel is worth testing if field arithmetic dominates. Preserve the JavaScript path and compare exact bytes and peak memory.

Use `local8` when losses fit per-stripe bounds and a catalog copy can be retained. Use `global16` when erasures may cluster or remove the catalog. Its pooled recovery budget costs more arithmetic as the archive grows. The parity percentage counts frames, and a corrupt byte can invalidate an entire frame. [Format and recovery bounds](format.md)
