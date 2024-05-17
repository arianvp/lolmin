# Benchmarks of NixOS eval time

With a minimal module list eval times seem to be almost twice as fast.

## Normal
```
Benchmark 1: nix path-info --derivation .#nixosConfigurations.aarch64-linux.config.system.build.toplevel --no-eval-cache
  Time (mean ± σ):      5.855 s ±  0.020 s    [User: 3.970 s, System: 0.587 s]
  Range (min … max):    5.822 s …  5.885 s    10 runs
```

## Minimal module list
```
Benchmark 1: nix path-info --derivation .#nixosConfigurations.aarch64-linux-minimal.config.system.build.toplevel --no-eval-cache
 
  Warning: The first benchmarking run for this command was significantly slower than the rest (3.537 s). This could be caused by (filesystem) caches that were not filled until after the first run. You are already using the '--warmup' option which helps to fill these caches before the actual benchmark. You can either try to increase the warmup count further or re-run this benchmark on a quiet system in case it was a random outlier. Alternatively, consider using the '--prepare' option to clear the caches before each timing run.
  Time (mean ± σ):      3.269 s ±  0.096 s    [User: 1.794 s, System: 0.377 s]
  Range (min … max):    3.212 s …  3.537 s    10 runs
```
