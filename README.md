# GRFP Archive Format

GRFP stores a lossless file recipe with Reed–Solomon parity. A reader can recover the original file and regenerate the archive when enough frames survive. Regrow-8 uses GRFP to protect circuit recipes. [Regrow-8 protection experiments](https://github.com/quietmaintainer/Regrow-8/blob/main/examples/file_recipe/PROTECTION.md)

## Pack and recover

Use Node.js 22 or later. The core codec uses Node's built-in modules.

```sh
node src/recipe.mjs pack input.bin archive.grfp --parity 5 --fec global16
node src/recipe.mjs recover archive.grfp recovered
```

Recovery writes `restored.bin`, the inner `recipe.grf` or `recipe.grl`, and a regenerated `protected.grfp` to a new directory. When an original file also survives in part, pass it with `--damaged path/to/file`. Verified original groups can supply missing recipe data.

| Layout | Recovery budget |
| --- | --- |
| `local8` | Each stripe has its own GF(2⁸) parity. The reader needs a surviving catalog copy. This is the default layout. |
| `global16` | GF(2¹⁶) parity covers the whole archive, including catalog shards. It can handle concentrated losses up to the archive's frame budget. |

The percentage sets a **frame** budget. Frame size, parity rounding, and catalog overhead determine the byte overhead. For a faster GRF1 pack on a particular input, try `--text off --templates off` and compare archive size. [Format details](docs/format.md) · [Performance review](docs/performance.md)

## Work with existing recipes

- Run `node src/recipe.mjs protect recipe.grf archive.grfp --parity 5 --fec global16` to protect an existing GRF1 recipe. Pass its original encoder options so its exact recipe bytes can be reproduced from verified source groups.
- Run `node src/recipe.mjs reprotect archive.grfp pooled.grfp --fec global16` to change the protection of an intact archive while retaining its encoded groups.
- Run `node src/long-cli.mjs --help` for the long-window codec, including `pack-shield` and `heal`. Protected long-window recipes use `global16`. The codec supports independent 256 KiB GRL1 and the restartable GRL2, GRL3, and GRL4 formats.

Run `npm install -g .` if you want the `grfp` and `grfp-long` commands on your path.

## Test and benchmark

```sh
npm test
npm run benchmark
npm run benchmark -- ../automaton-swarm/examples/file_recipe
```

The tests include the published Regrow-8 CPU and ALU archives. They delete the recipe frame and check both the recovered source and the regenerated archive. For optional lattice tests, set `SWARM_WEB` to a built Automaton Swarm `web` directory.

The included C predictor can be compiled with Python, Clang, and `wasm-ld` using `python src/build_predictor.py predictor.wasm`. Set `GRL_PREDICTOR_WASM` to the built module's path to enable its tests and benchmark. Select it with `--backend wasm` on long-window commands such as `pack-restart` and `heal`.

## Origin and license

This repository extracts the file recipe codec developed in Automaton Worm and maintained in Automaton Swarm. The original MIT notice credits the Automaton Worm contributors. [License](LICENSE)
