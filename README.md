# Trident
Trident is a benchmark suite based on [Poseidon](https://poseidon-hpu.readthedocs.io/en/latest/Getting_Started/Installation/Installation.html) library.
Download and install Poseidon (follow the instructions in the above link) before testing Trident.

## Compiling Trident
Once Poseidon library is installed, to build Trident simply run:
```
./trident build [example]
```
This should produce a binary file `example/build/example`.

## Testing Trident
Once you have compiled Trident, you can run our benchmark tests with:
```
./trident run [example]
```
## Supplement
- "example" in command line can be omitted to execute the command on each benchmark.
- More parameters can be added on some specific benchmarks.