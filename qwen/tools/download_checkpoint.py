#!/usr/bin/env python3
"""Resumable HTTP Range downloader for large, immutable model files."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import os
from pathlib import Path
import shutil
import sys
import time
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--parts-dir", type=Path, required=True)
    parser.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--retries", type=int, default=12)
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def download_part(
    url: str,
    parts_dir: Path,
    index: int,
    start: int,
    end: int,
    total_size: int,
    retries: int,
) -> Path:
    expected_size = end - start + 1
    destination = parts_dir / f"part-{index:04d}"
    if destination.exists() and destination.stat().st_size == expected_size:
        return destination

    temporary = parts_dir / f"part-{index:04d}.tmp"
    temporary.unlink(missing_ok=True)
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "Range": f"bytes={start}-{end}",
                    "User-Agent": "poseidon-qwen-checkpoint-downloader/1.0",
                },
            )
            with urllib.request.urlopen(request, timeout=300) as response:
                if response.status != 206:
                    raise RuntimeError(f"range request returned HTTP {response.status}")
                expected_range = f"bytes {start}-{end}/{total_size}"
                actual_range = response.headers.get("Content-Range")
                if actual_range != expected_range:
                    raise RuntimeError(
                        f"unexpected Content-Range {actual_range!r}, expected {expected_range!r}"
                    )
                with temporary.open("wb") as output:
                    shutil.copyfileobj(response, output, length=1024 * 1024)
            actual_size = temporary.stat().st_size
            if actual_size != expected_size:
                raise RuntimeError(
                    f"part {index} has {actual_size} bytes, expected {expected_size}"
                )
            os.replace(temporary, destination)
            return destination
        except Exception as error:
            last_error = error
            temporary.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(min(2 * attempt, 15))
    raise RuntimeError(f"failed to download part {index}: {last_error}")


def merge_parts(args: argparse.Namespace, part_count: int) -> None:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    digest = hashlib.sha256()
    written = 0
    with temporary.open("wb") as output:
        for index in range(part_count):
            part = args.parts_dir / f"part-{index:04d}"
            with part.open("rb") as source:
                while block := source.read(8 * 1024 * 1024):
                    output.write(block)
                    digest.update(block)
                    written += len(block)
    if written != args.size:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"merged file has {written} bytes, expected {args.size}")
    actual_hash = digest.hexdigest()
    if actual_hash != args.sha256.lower():
        temporary.unlink(missing_ok=True)
        raise RuntimeError(
            f"SHA-256 mismatch: got {actual_hash}, expected {args.sha256.lower()}"
        )
    os.replace(temporary, args.output)


def main() -> int:
    args = parse_args()
    if args.size <= 0 or args.chunk_size <= 0 or args.workers <= 0 or args.retries <= 0:
        raise ValueError("size, chunk size, workers, and retries must be positive")
    if len(args.sha256) != 64:
        raise ValueError("SHA-256 must contain 64 hexadecimal characters")

    if args.output.exists() and args.output.stat().st_size == args.size:
        actual_hash = file_sha256(args.output)
        if actual_hash == args.sha256.lower():
            print(f"already verified: {args.output}")
            return 0

    args.parts_dir.mkdir(parents=True, exist_ok=True)
    part_count = (args.size + args.chunk_size - 1) // args.chunk_size
    completed = 0
    futures: dict[concurrent.futures.Future[Path], int] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for index in range(part_count):
            start = index * args.chunk_size
            end = min(args.size - 1, start + args.chunk_size - 1)
            future = executor.submit(
                download_part,
                args.url,
                args.parts_dir,
                index,
                start,
                end,
                args.size,
                args.retries,
            )
            futures[future] = index
        for future in concurrent.futures.as_completed(futures):
            future.result()
            completed += 1
            print(f"downloaded parts: {completed}/{part_count}", flush=True)

    merge_parts(args, part_count)
    print(f"verified SHA-256: {args.sha256.lower()}")
    print(args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"download_checkpoint: {error}", file=sys.stderr)
        raise SystemExit(1)
