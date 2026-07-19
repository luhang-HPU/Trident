# ResNet-50 ImageNet Encrypted Inference

This directory mirrors the ResNet-18 demo layout and implements an ImageNet
ResNet-50 bottleneck network with encrypted convolution, batch norm, polynomial
ReLU, residual add, global average pooling, and fully connected head.

Export torchvision weights before running:

```bash
python3 export_torchvision_resnet50_txt.py \
  --input pretrained_parameters/resnet50-11ad3fa6.pth
```

When `--input` is omitted, the exporter tries common local torchvision filenames
such as `resnet50-11ad3fa6.pth` and `resnet50-0676ba61.pth`.

The ImageNet test subset is loaded from this package's `testFile` directory.
ReLU approximation parameters still fall back to `../resnet18/relu_param` when
a local `relu_param` directory is not present.

For a fast smoke path that refreshes ciphertexts from the synchronized plain
reference at nonlinear refresh points:

```bash
RESNET50_MOCK_RELU=1 RESNET50_MOCK_BOOTSTRAP=1 ./resnet50 0 0
```
