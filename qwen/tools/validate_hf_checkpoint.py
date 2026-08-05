#!/usr/bin/env python3
"""Compare the CPU C++ Qwen path with the official Transformers implementation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForCausalLM


QWEN_DIRECTORY = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = QWEN_DIRECTORY / "pretrained_parameters" / "Qwen2.5-0.5B"
DEFAULT_BINARY = QWEN_DIRECTORY.parent / "build" / "qwen" / "qwen_plain"
DEFAULT_OUTPUT = QWEN_DIRECTORY / "validation_output"


def parse_ids(text: str) -> list[int]:
    try:
        values = [int(value.strip()) for value in text.replace(" ", ",").split(",") if value.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError("input IDs must be integers") from error
    if not values or any(value < 0 for value in values):
        raise argparse.ArgumentTypeError("input IDs must be a nonempty list of nonnegative integers")
    return values


def save_tensor(directory: Path, name: str, tensor: torch.Tensor) -> np.ndarray:
    value = tensor.detach().cpu().to(torch.float64).numpy().squeeze(0)
    value.tofile(directory / f"{name}.f64")
    return value


def export_hugging_face(
    model_directory: Path,
    input_ids: list[int],
    max_new_tokens: int,
    output_directory: Path,
) -> tuple[dict[str, np.ndarray], list[int], float, float]:
    output_directory.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    model = AutoModelForCausalLM.from_pretrained(
        model_directory,
        local_files_only=True,
        dtype=torch.float64,
        attn_implementation="eager",
    )
    model.eval()
    load_seconds = time.perf_counter() - started

    captured: dict[str, torch.Tensor] = {}
    hooks = [
        model.model.embed_tokens.register_forward_hook(
            lambda _module, _inputs, output: captured.__setitem__("embedding", output)
        ),
        model.model.norm.register_forward_hook(
            lambda _module, _inputs, output: captured.__setitem__("final_rmsnorm", output)
        ),
    ]
    for index, layer in enumerate(model.model.layers):
        hooks.append(
            layer.register_forward_hook(
                lambda _module, _inputs, output, layer_index=index: captured.__setitem__(
                    f"layer_{layer_index}.output", output
                )
            )
        )

    tokens = torch.tensor([input_ids], dtype=torch.long)
    started = time.perf_counter()
    with torch.no_grad():
        result = model(
            input_ids=tokens,
            use_cache=False,
            output_hidden_states=False,
            return_dict=True,
        )
    for hook in hooks:
        hook.remove()
    with torch.no_grad():
        generated = model.generate(
            input_ids=tokens,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            use_cache=True,
        )
    inference_seconds = time.perf_counter() - started

    references: dict[str, np.ndarray] = {}
    for name, tensor in captured.items():
        references[name] = save_tensor(output_directory, name, tensor)
    references["last_token_logits"] = save_tensor(
        output_directory, "last_token_logits", result.logits[:, -1:, :]
    )
    generated_ids = generated[0, len(input_ids) :].tolist()

    metadata = {
        "model": str(model_directory),
        "input_ids": input_ids,
        "dtype": "float64",
        "attention": "eager",
        "generated_token_ids": generated_ids,
        "load_seconds": load_seconds,
        "inference_seconds": inference_seconds,
        "shapes": {name: list(value.shape) for name, value in references.items()},
    }
    (output_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    return references, generated_ids, load_seconds, inference_seconds


def run_cpp(
    binary: Path,
    model_directory: Path,
    input_ids: list[int],
    threads: int,
    output_directory: Path,
) -> tuple[str, float]:
    started = time.perf_counter()
    process = subprocess.run(
        [
            str(binary),
            "--model",
            str(model_directory),
            "--input-ids",
            ",".join(str(value) for value in input_ids),
            "--top-k",
            "5",
            "--threads",
            str(threads),
            "--dump-trace-dir",
            str(output_directory),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return process.stdout, time.perf_counter() - started


def run_cpp_generation(
    binary: Path,
    model_directory: Path,
    input_ids: list[int],
    max_new_tokens: int,
    threads: int,
) -> tuple[list[int], float]:
    started = time.perf_counter()
    process = subprocess.run(
        [
            str(binary),
            "--model",
            str(model_directory),
            "--input-ids",
            ",".join(str(value) for value in input_ids),
            "--max-new-tokens",
            str(max_new_tokens),
            "--threads",
            str(threads),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    prefix = "generated_token_ids:"
    for line in process.stdout.splitlines():
        if line.startswith(prefix):
            return [int(value) for value in line[len(prefix) :].split()], time.perf_counter() - started
    raise RuntimeError("C++ output did not contain generated_token_ids")


def compare(
    references: dict[str, np.ndarray], cpp_directory: Path, atol: float, rtol: float
) -> tuple[list[dict[str, float | str]], bool]:
    rows: list[dict[str, float | str]] = []
    passed = True
    for name, reference in references.items():
        path = cpp_directory / f"{name}.f64"
        if not path.is_file():
            raise FileNotFoundError(f"C++ trace is missing {path}")
        actual = np.fromfile(path, dtype=np.float64).reshape(reference.shape)
        difference = np.abs(actual - reference)
        row_passed = bool(np.allclose(actual, reference, atol=atol, rtol=rtol))
        passed = passed and row_passed
        rows.append(
            {
                "name": name,
                "max_abs": float(difference.max(initial=0.0)),
                "mean_abs": float(difference.mean()),
                "rmse": float(np.sqrt(np.mean(np.square(difference)))),
                "passed": "yes" if row_passed else "no",
            }
        )
    return rows, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--input-ids", type=parse_ids, default=parse_ids("9707,11,847"))
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--max-new-tokens", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--atol", type=float, default=2e-4)
    parser.add_argument("--rtol", type=float, default=2e-5)
    args = parser.parse_args()

    if args.threads <= 0:
        parser.error("--threads must be positive")
    if args.max_new_tokens <= 0:
        parser.error("--max-new-tokens must be positive")
    if not args.model.is_dir():
        parser.error(f"model directory does not exist: {args.model}")
    if not args.binary.is_file():
        parser.error(f"C++ binary does not exist: {args.binary}")

    hf_directory = args.output_dir / "huggingface"
    cpp_directory = args.output_dir / "cpp"
    hf_directory.mkdir(parents=True, exist_ok=True)
    cpp_directory.mkdir(parents=True, exist_ok=True)

    print(f"model: {args.model}")
    print(f"input_ids: {args.input_ids}")
    references, hf_generated, hf_load, hf_inference = export_hugging_face(
        args.model, args.input_ids, args.max_new_tokens, hf_directory
    )
    cpp_output, cpp_total = run_cpp(
        args.binary, args.model, args.input_ids, args.threads, cpp_directory
    )
    rows, passed = compare(references, cpp_directory, args.atol, args.rtol)
    cpp_generated, cpp_generation_total = run_cpp_generation(
        args.binary,
        args.model,
        args.input_ids,
        args.max_new_tokens,
        args.threads,
    )
    generation_passed = cpp_generated == hf_generated
    passed = passed and generation_passed

    print("\nnode                         max_abs       mean_abs      rmse          pass")
    for row in rows:
        print(
            f"{row['name']:<28} {row['max_abs']:<13.6e} "
            f"{row['mean_abs']:<13.6e} {row['rmse']:<13.6e} {row['passed']}"
        )
    print(f"\nHugging Face: load={hf_load:.3f}s inference={hf_inference:.3f}s")
    print(f"C++ process total: {cpp_total:.3f}s")
    print("C++ top logits:")
    for line in cpp_output.splitlines():
        if line.startswith("  token="):
            print(line)
    print(f"HF generated:  {hf_generated}")
    print(f"C++ generated: {cpp_generated}")
    print(
        f"greedy generation: {'PASS' if generation_passed else 'FAIL'} "
        f"({args.max_new_tokens} tokens, C++ total={cpp_generation_total:.3f}s)"
    )
    print(f"result: {'PASS' if passed else 'FAIL'} (atol={args.atol:g}, rtol={args.rtol:g})")
    print(f"artifacts: {args.output_dir}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
