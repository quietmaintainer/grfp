"""Build the optional GRL2 accelerator using clang and wasm-ld, without a WASI SDK."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path);args=p.parse_args()
if args.output.exists():raise FileExistsError(args.output)
src=Path(__file__).with_name('predictor-wasm.c');clang=os.environ.get('CLANG') or shutil.which('clang')
if not clang:raise RuntimeError('clang with wasm32 target required')
with tempfile.TemporaryDirectory(dir=args.output.parent) as tmp:
    binary=Path(tmp)/'model.wasm'
    subprocess.run([clang,'--target=wasm32','-std=c11','-O3','-mbulk-memory','-nostdlib','-fno-builtin','-Wl,--no-entry',
                    '-Wl,--export-memory','-Wl,--max-memory=536870912','-Wl,--strip-all','-Wl,-z,stack-size=131072',src,'-o',binary],check=True)
    with binary.open('rb') as f,args.output.open('xb') as out:shutil.copyfileobj(f,out)
print(f'{args.output}: {args.output.stat().st_size} bytes')
