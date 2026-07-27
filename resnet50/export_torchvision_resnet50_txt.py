#!/usr/bin/env python3
"""Export torchvision ResNet-50 ImageNet weights to txt files used by this demo."""

from __future__ import annotations

import argparse
from pathlib import Path

import torch


def output_name(key: str) -> str:
    return key.replace(".", "_") + ".txt"


def write_tensor(path: Path, tensor: torch.Tensor) -> None:
    flat = tensor.detach().cpu().reshape(-1)
    with path.open("w", encoding="utf-8") as output:
        for index, value in enumerate(flat):
            if index:
                output.write(" ")
            output.write(f"{float(value):.9g}")
        output.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to a torchvision ResNet-50 .pth file. If omitted, common local filenames are tried.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent / "pretrained_parameters" / "resnet50_imagenet",
    )
    args = parser.parse_args()

    input_path = args.input
    if input_path is None:
        root = Path(__file__).parent / "pretrained_parameters"
        for candidate in ("resnet50-11ad3fa6.pth", "resnet50-0676ba61.pth"):
            path = root / candidate
            if path.exists():
                input_path = path
                break
    if input_path is None:
        raise FileNotFoundError("no ResNet-50 .pth file found in pretrained_parameters")

    state = torch.load(input_path, map_location="cpu")
    if isinstance(state, dict) and "state_dict" in state:
        state = state["state_dict"]

    args.output.mkdir(parents=True, exist_ok=True)
    for key, value in state.items():
        if key.endswith("num_batches_tracked"):
            continue
        write_tensor(args.output / output_name(key), value)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
