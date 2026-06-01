# ResNet-20

This directory contains a Trident-side ResNet-20 port that follows the weight layout,
test-data layout, command-line interface, and result-file naming used in
`/home/guoshuai/github/FHE-MP-CNN`.

## What is implemented

- ResNet-20 CIFAR-10 inference with the `resnet20_new` pretrained parameters.
- The same `start_image_id end_image_id` execution style as the original project.
- Result files written to `result/resnet20_cifar10_image<ID>.txt` and
  `result/resnet20_cifar10_label_<START>_<END>`.
- An optional Poseidon CKKS round-trip sanity check for the final logits.
- An experimental `--mode he` path that runs a Poseidon CKKS operator pipeline on
  encrypted per-channel feature maps.
- The HE activation now follows `FHE-MP-CNN`'s composite minimax ReLU
  (`alpha=13`, `deg={15,15,27}`, coefficients from `cnn_ckks/result/d13.txt`),
  and the residual blocks insert bootstrap before each HE activation just like
  the original pipeline.

## Current scope

This Trident version now has a validated plaintext reference path and a work-in-progress
homomorphic path. The HE mode is useful for operator bring-up and plaintext-vs-HE
comparison, but it is not yet a complete paper-faithful port of the full
multiplexed-parallel pipeline in `LCDCNN.pdf`.

## Build

From `Trident/build`:

```bash
cmake ..
make resnet20
```

## Run

The basic interface matches the existing `trident` helper script:

```bash
cd /home/guoshuai/github/poseidon/Trident/resnet20
./build/resnet20 0 0
```

Optional flags:

```bash
./build/resnet20 0 0 \
  --weights-root /home/guoshuai/github/FHE-MP-CNN/pretrained_parameters/resnet20_new \
  --data-root /home/guoshuai/github/FHE-MP-CNN/testFile \
  --input-layout chw \
  --weight-layout oihw \
  --poseidon-roundtrip
```

Experimental HE bring-up:

```bash
./build/resnet20 0 0 --mode he --he-block-limit 0
```

The HE path reads the original ReLU coefficients by default from
`/home/guoshuai/github/FHE-MP-CNN/cnn_ckks/result/d13.txt`. You can override it:

```bash
./build/resnet20 0 0 --mode he --he-block-limit 0 \
  --he-activation fhe_mp_cnn_relu \
  --relu-coeffs /home/guoshuai/github/FHE-MP-CNN/cnn_ckks/result/d13.txt
```

## Defaults

If flags are omitted, the executable tries:

1. `TRIDENT_RESNET20_WEIGHTS_ROOT`
2. `TRIDENT_RESNET20_DATA_ROOT`
3. `TRIDENT_RESNET20_RELU_COEFFS`
4. `/home/guoshuai/github/FHE-MP-CNN/pretrained_parameters/resnet20_new`
5. `/home/guoshuai/github/FHE-MP-CNN/testFile`
6. `/home/guoshuai/github/FHE-MP-CNN/cnn_ckks/result/d13.txt`

## Notes

- `--input-layout` supports `hwc` and `chw`.
- `--weight-layout` supports `oihw` and `hwio`.
- `--mode` supports `plaintext` and `he`.
- `--he-block-limit` limits how many residual blocks the HE path executes.
- `--he-activation` accepts `fhe_mp_cnn_relu` and `poly_relu` as the same
  FHE-MP-CNN-compatible activation.
- `--relu-coeffs` points to the original `d13.txt` coefficient file.
- The default combination is `chw + oihw`, which matches the current reference files.
