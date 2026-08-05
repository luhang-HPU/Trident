# Qwen CPU Plaintext Inference

This directory contains the CPU reference path that will be used to validate the
future CKKS implementation. It currently implements:

Detailed architecture and operator documentation:
[ARCHITECTURE.md](ARCHITECTURE.md).

Current Chinese progress report and presentation summary:
[PROGRESS_REPORT_20260803_ZH.md](PROGRESS_REPORT_20260803_ZH.md).

CKKS design, implementation status, validation results, and commands:
[HE_INFERENCE_PLAN.md](HE_INFERENCE_PLAN.md).

ResNet-style reduced-depth Chebyshev evaluation and level accounting:
[HE_LOW_DEPTH_CHEBYSHEV_ZH.md](HE_LOW_DEPTH_CHEBYSHEV_ZH.md).

- Hugging Face `config.json` parsing
- single-file and sharded `safetensors` loading
- F64, F32, F16, and BF16 weight conversion
- token embedding and the complete decoder layer stack
- RMSNorm
- Q/K/V projections with optional bias
- Qwen split-half RoPE
- causal grouped-query attention
- prefill and decode KV cache
- output projection and residual
- RMSNorm and SwiGLU MLP
- final RMSNorm and LM head
- top-k logits and greedy token-ID generation

With no arguments, the executable uses a deterministic small configuration and
synthetic weights. This keeps core correctness tests independent of model
downloads. A real checkpoint can be supplied with `--model`; input currently
uses token IDs so the C++ inference core does not depend on a tokenizer library.

Build and run:

```bash
cmake -S . -B build
cmake --build build --target qwen_plain qwen_plain_tests -j2
./build/qwen/qwen_plain_tests
./build/qwen/qwen_plain --sequence 8 --threads 4
```

Run a real Qwen2/2.5 checkpoint:

```bash
./build/qwen/qwen_plain \
  --model /path/to/Qwen2.5-0.5B \
  --input-ids 1,9707,11 \
  --top-k 5 \
  --threads 16
```

Greedy generation:

```bash
./build/qwen/qwen_plain \
  --model /path/to/Qwen2.5-0.5B \
  --input-ids 1,9707,11 \
  --max-new-tokens 8 \
  --threads 16
```

The plaintext implementation intentionally uses the same operator boundaries
planned for the encrypted path. It does not link Poseidon and has no GPU
dependency.

## Official Qwen2.5-0.5B validation

Download the official base checkpoint into:

```text
Trident/qwen/pretrained_parameters/Qwen2.5-0.5B
```

Then run the reproducible CPU comparison:

```bash
python3 Trident/qwen/tools/validate_hf_checkpoint.py --threads 16
```

The validator runs the local checkpoint through Hugging Face Transformers with
eager attention and float64 parameters, runs the C++ executable with the same
token IDs, and compares the embedding, every decoder-layer output, final
RMSNorm, last-token logits, and eight greedy KV-cache decode steps. Raw
comparison tensors are written to `Trident/qwen/validation_output`.
