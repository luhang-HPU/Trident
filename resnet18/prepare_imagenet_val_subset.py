#!/usr/bin/env python3
"""Prepare ImageNet validation images for the ResNet-18 HE inference demo."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable

from PIL import Image


MEAN = (0.485, 0.456, 0.406)
STD = (0.229, 0.224, 0.225)


def resample_bilinear():
    if hasattr(Image, "Resampling"):
        return Image.Resampling.BILINEAR
    return Image.BILINEAR


def load_synset_to_index(path: Path) -> dict[str, int]:
    mapping: dict[str, int] = {}
    with path.open("r", encoding="utf-8") as input_file:
        for index, line in enumerate(input_file):
            line = line.strip()
            if not line:
                continue
            synset = line.split(maxsplit=1)[0]
            mapping[synset] = index
    if len(mapping) != 1000:
        raise ValueError(f"expected 1000 synsets, got {len(mapping)}")
    return mapping


def load_solution(path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    with path.open("r", encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            image_id = row["ImageId"]
            prediction = row["PredictionString"].split()
            if not prediction:
                raise ValueError(f"empty prediction string for {image_id}")
            labels[image_id] = prediction[0]
    return labels


def image_sort_key(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def resize_shorter_side(image: Image.Image, size: int) -> Image.Image:
    width, height = image.size
    if width <= 0 or height <= 0:
        raise ValueError("invalid image size")
    if width < height:
        new_width = size
        new_height = round(height * size / width)
    else:
        new_height = size
        new_width = round(width * size / height)
    return image.resize((new_width, new_height), resample=resample_bilinear())


def center_crop(image: Image.Image, size: int) -> Image.Image:
    width, height = image.size
    left = (width - size) // 2
    top = (height - size) // 2
    return image.crop((left, top, left + size, top + size))


def preprocess_image(path: Path, resize: int, crop: int) -> list[float]:
    with Image.open(path) as image:
        image = image.convert("RGB")
        image = resize_shorter_side(image, resize)
        image = center_crop(image, crop)
        pixels = list(image.getdata())

    values: list[float] = []
    for channel in range(3):
        mean = MEAN[channel]
        std = STD[channel]
        values.extend(((pixel[channel] / 255.0) - mean) / std for pixel in pixels)
    return values


def iter_selected_images(image_dir: Path, limit: int | None) -> Iterable[Path]:
    images = sorted(image_dir.glob("ILSVRC2012_val_*.JPEG"), key=image_sort_key)
    if limit is not None:
        images = images[:limit]
    return images


def main() -> int:
    root = Path(__file__).parent / "testFile"
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--image-dir", type=Path, default=root / "val")
    parser.add_argument("--solution", type=Path, default=root / "LOC_val_solution.csv")
    parser.add_argument("--synset-mapping", type=Path, default=root / "LOC_synset_mapping.txt")
    parser.add_argument("--values-out", type=Path, default=root / "test_values.txt")
    parser.add_argument("--labels-out", type=Path, default=root / "test_label.txt")
    parser.add_argument("--manifest-out", type=Path, default=root / "test_manifest.txt")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resize", type=int, default=256)
    parser.add_argument("--crop", type=int, default=224)
    args = parser.parse_args()

    synset_to_index = load_synset_to_index(args.synset_mapping)
    solution = load_solution(args.solution)
    images = list(iter_selected_images(args.image_dir, args.limit))
    if not images:
        raise ValueError(f"no validation images found in {args.image_dir}")

    args.values_out.parent.mkdir(parents=True, exist_ok=True)
    with args.values_out.open("w", encoding="utf-8") as values_out, \
            args.labels_out.open("w", encoding="utf-8") as labels_out, \
            args.manifest_out.open("w", encoding="utf-8") as manifest_out:
        manifest_out.write("image_id\tfile\tsynset\tlabel\n")
        for image_id, image_path in enumerate(images):
            original_id = image_path.stem
            if original_id not in solution:
                raise ValueError(f"missing solution for {original_id}")
            synset = solution[original_id]
            if synset not in synset_to_index:
                raise ValueError(f"unknown synset {synset} for {original_id}")
            label = synset_to_index[synset]

            values = preprocess_image(image_path, args.resize, args.crop)
            values_out.write(" ".join(f"{value:.9g}" for value in values))
            values_out.write("\n")
            labels_out.write(f"{label}\n")
            manifest_out.write(f"{image_id}\t{image_path.name}\t{synset}\t{label}\n")

            if image_id % 50 == 0:
                print(f"processed {image_id + 1}/{len(images)}: {image_path.name}")

    print(f"wrote {len(images)} images")
    print(f"values: {args.values_out}")
    print(f"labels: {args.labels_out}")
    print(f"manifest: {args.manifest_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
