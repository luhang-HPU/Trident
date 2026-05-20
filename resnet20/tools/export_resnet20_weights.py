#!/usr/bin/env python3
"""Export CIFAR-10 ResNet-20 PyTorch weights for the Trident HE demo.

The C++ ResNet-20 loader intentionally reads only simple float32 files. This
script does the PyTorch-specific work: load a checkpoint, fold BatchNorm into
Conv2d/Linear-compatible tensors, and write a stable directory layout.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

torch: Any = None


CHENYAFO_CIFAR10_RESNET20_URL = (
    "https://github.com/chenyaofo/pytorch-cifar-models/releases/download/resnet/"
    "cifar10_resnet20-4118986f.pt"
)


TensorMap = Mapping[str, Any]


def ensure_python_deps() -> None:
    global torch
    if torch is not None:
        return
    try:
        import torch as torch_module
    except ModuleNotFoundError as exc:
        missing = exc.name or "torch"
        raise SystemExit(
            f"Missing Python dependency '{missing}'. Install dependencies with:\n"
            "  python3 -m pip install torch\n"
            "Then rerun this export script."
        ) from exc
    torch = torch_module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export pretrained CIFAR-10 ResNet-20 weights for Trident/resnet20."
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        help="Path to a PyTorch .pt/.pth/.th checkpoint. If omitted, --source-url is used.",
    )
    parser.add_argument(
        "--source-url",
        default=CHENYAFO_CIFAR10_RESNET20_URL,
        help="URL passed to torch.hub.load_state_dict_from_url when --checkpoint is omitted.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Output directory for manifest.json and *.f32 files.",
    )
    parser.add_argument(
        "--source-name",
        default="chenyaofo_cifar10_resnet20",
        help="Metadata string written to manifest.json.",
    )
    parser.add_argument(
        "--activation",
        default="relu_bn_folded",
        choices=("relu_bn_folded", "square_bn_folded", "square"),
        help=(
            "Metadata only. Public checkpoints are usually relu_bn_folded; "
            "HE-friendly retrained checkpoints should use square_bn_folded or square."
        ),
    )
    return parser.parse_args()


def unwrap_checkpoint(obj: object) -> Dict[str, torch.Tensor]:
    ensure_python_deps()
    if isinstance(obj, dict):
        for key in ("state_dict", "model_state_dict", "net", "model"):
            nested = obj.get(key)
            if isinstance(nested, dict):
                obj = nested
                break

    if not isinstance(obj, dict):
        raise TypeError("checkpoint does not contain a state_dict-like mapping")

    state: Dict[str, torch.Tensor] = {}
    for key, value in obj.items():
        if not torch.is_tensor(value):
            continue
        normalized = key
        for prefix in ("module.", "model."):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        state[normalized] = value.detach().cpu().float()
    return state


def load_state(args: argparse.Namespace) -> Dict[str, torch.Tensor]:
    ensure_python_deps()
    if args.checkpoint is not None:
        checkpoint = torch.load(args.checkpoint, map_location="cpu")
    else:
        checkpoint = torch.hub.load_state_dict_from_url(args.source_url, map_location="cpu")
    return unwrap_checkpoint(checkpoint)


def pick_existing(state: TensorMap, candidates: Iterable[str]) -> str:
    for name in candidates:
        if name in state:
            return name
    raise KeyError(f"none of these checkpoint keys exist: {', '.join(candidates)}")


def get_tensor(state: TensorMap, name: str) -> torch.Tensor:
    try:
        return state[name]
    except KeyError as exc:
        raise KeyError(f"missing checkpoint tensor: {name}") from exc


def fold_conv_bn(
    state: TensorMap,
    conv_prefix: str,
    bn_prefix: Optional[str],
    eps: float = 1e-5,
) -> Tuple[Any, Any]:
    weight = get_tensor(state, f"{conv_prefix}.weight")
    bias_key = f"{conv_prefix}.bias"
    bias = state.get(bias_key, torch.zeros(weight.shape[0], dtype=weight.dtype))

    if bn_prefix is None:
        return weight.contiguous(), bias.contiguous()

    gamma = get_tensor(state, f"{bn_prefix}.weight")
    beta = get_tensor(state, f"{bn_prefix}.bias")
    mean = get_tensor(state, f"{bn_prefix}.running_mean")
    var = get_tensor(state, f"{bn_prefix}.running_var")

    scale = gamma / torch.sqrt(var + eps)
    folded_weight = weight * scale.reshape(-1, 1, 1, 1)
    folded_bias = beta + (bias - mean) * scale
    return folded_weight.contiguous(), folded_bias.contiguous()


def to_float_list(tensor: Any) -> List[float]:
    return [float(value) for value in tensor.detach().cpu().contiguous().view(-1).tolist()]


def write_floats(out_dir: Path, name: str, values: Iterable[float]) -> None:
    values_list = list(values)
    path = out_dir / f"{name}.f32"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<" + "f" * len(values_list), *values_list))


def write_tensor(out_dir: Path, name: str, tensor: Any) -> None:
    write_floats(out_dir, name, to_float_list(tensor))


def export_conv(
    out_dir: Path,
    output_prefix: str,
    state: TensorMap,
    conv_prefix: str,
    bn_prefix: Optional[str],
) -> None:
    weight, bias = fold_conv_bn(state, conv_prefix, bn_prefix)
    write_tensor(out_dir, f"{output_prefix}.weight", weight)
    write_tensor(out_dir, f"{output_prefix}.bias", bias)


def export_option_a_shortcut(
    out_dir: Path,
    output_prefix: str,
    in_channels: int,
    out_channels: int,
) -> None:
    weight = [0.0] * (out_channels * in_channels)
    offset = (out_channels - in_channels) // 2
    for channel in range(in_channels):
        weight[(offset + channel) * in_channels + channel] = 1.0
    bias = [0.0] * out_channels
    write_floats(out_dir, f"{output_prefix}.weight", weight)
    write_floats(out_dir, f"{output_prefix}.bias", bias)


def layer_prefix(stage: int, block: int) -> str:
    return f"layer{stage}.{block}"


def checkpoint_has_chenyaofo_downsample(state: TensorMap, prefix: str) -> bool:
    return f"{prefix}.downsample.0.weight" in state


def export_block(
    out_dir: Path,
    state: TensorMap,
    output_prefix: str,
    pytorch_prefix: str,
    in_channels: int,
    out_channels: int,
    stride: int,
) -> None:
    export_conv(out_dir, f"{output_prefix}.conv1", state,
                f"{pytorch_prefix}.conv1", f"{pytorch_prefix}.bn1")
    export_conv(out_dir, f"{output_prefix}.conv2", state,
                f"{pytorch_prefix}.conv2", f"{pytorch_prefix}.bn2")

    if in_channels == out_channels and stride == 1:
        return

    if checkpoint_has_chenyaofo_downsample(state, pytorch_prefix):
        export_conv(out_dir, f"{output_prefix}.shortcut", state,
                    f"{pytorch_prefix}.downsample.0", f"{pytorch_prefix}.downsample.1")
    else:
        # akamaster uses ResNet option A: strided identity plus zero-padded channels.
        export_option_a_shortcut(out_dir, f"{output_prefix}.shortcut",
                                 in_channels, out_channels)


def export_fc(out_dir: Path, state: TensorMap) -> None:
    weight_key = pick_existing(state, ("fc.weight", "linear.weight"))
    bias_key = pick_existing(state, ("fc.bias", "linear.bias"))
    write_tensor(out_dir, "fc.weight", get_tensor(state, weight_key))
    write_tensor(out_dir, "fc.bias", get_tensor(state, bias_key))


def write_manifest(args: argparse.Namespace, out_dir: Path) -> None:
    manifest = {
        "format": "poseidon_resnet20_weights_v1",
        "source": args.source_name,
        "activation": args.activation,
        "num_classes": 10,
        "layout": "chw",
        "dtype": "float32_little_endian",
        "note": (
            "BatchNorm has been folded into conv weights/bias. Public ReLU "
            "checkpoints are useful for loading tests, but HE accuracy requires "
            "weights trained for the polynomial activation used by Trident."
        ),
        "files": "*.f32",
    }
    with (out_dir / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")


def main() -> None:
    args = parse_args()
    ensure_python_deps()
    state = load_state(args)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    export_conv(out_dir, "conv1", state, "conv1", "bn1")

    for block in range(3):
        export_block(out_dir, state, f"stage1.{block}", layer_prefix(1, block),
                     16, 16, 1)
    export_block(out_dir, state, "stage2.0", layer_prefix(2, 0), 16, 32, 2)
    export_block(out_dir, state, "stage2.1", layer_prefix(2, 1), 32, 32, 1)
    export_block(out_dir, state, "stage2.2", layer_prefix(2, 2), 32, 32, 1)
    export_block(out_dir, state, "stage3.0", layer_prefix(3, 0), 32, 64, 2)
    export_block(out_dir, state, "stage3.1", layer_prefix(3, 1), 64, 64, 1)
    export_block(out_dir, state, "stage3.2", layer_prefix(3, 2), 64, 64, 1)
    export_fc(out_dir, state)
    write_manifest(args, out_dir)

    print(f"Exported ResNet-20 weights to {out_dir}")
    print("Use with: Trident/build/resnet20/resnet20 --parameters", out_dir)


if __name__ == "__main__":
    main()
