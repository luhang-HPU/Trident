# ResNet18 ImageNet Poseidon Inference

这个目录实现 ImageNet 版 ResNet-18 的 Poseidon CKKS 密文推理骨架，输入尺寸为
`224x224x3`，输出为 `1000` 类 logits。

## Build

```bash
cmake -S Trident -B Trident/build -DRESNET18=ON
cmake --build Trident/build --target resnet18 -j2
cmake --build Trident/build --target resnet18_plain -j2
```

当前 `resnet18` 是密文入口。Poseidon 目前 `logN` 最大为 `16`，单个 CKKS
ciphertext 只有 `32768` slots，而一张 ImageNet 输入有 `224*224*3=150528`
个值。因此密文入口已经使用 `TensorCipherGroup` 按通道把一张图拆成 6 个 ciphertext
加密，并会解密回读检查输入误差：

```bash
./Trident/build/resnet18/resnet18 START_IMAGE_ID END_IMAGE_ID
```

当前密文入口会完成：

```text
ImageNet input -> 6 ciphertext TensorCipherGroup
conv1 output[0..3] encrypted dot-product preview
conv1 im2col packing -> encrypted conv1 output channel 0
```

`conv1` 的前几个输出和完整输出通道 0 都会和明文 conv1 对照误差。完整 64
个输出通道封装成 conv1 output group 仍是下一步。

纯明文验证入口：

```bash
./Trident/build/resnet18/resnet18_plain START_IMAGE_ID END_IMAGE_ID
```

`START_IMAGE_ID` 和 `END_IMAGE_ID` 是闭区间。建议先跑：

```bash
./Trident/build/resnet18/resnet18_plain 0 0
```

## Network

执行顺序：

```text
7x7 stride-2 conv -> bn -> relu
3x3 stride-2 maxpool in the plain reference path
layer1: 2 BasicBlock, 64 channels
layer2: 2 BasicBlock, 128 channels, first block stride 2 + projection shortcut
layer3: 2 BasicBlock, 256 channels, first block stride 2 + projection shortcut
layer4: 2 BasicBlock, 512 channels, first block stride 2 + projection shortcut
global average pool -> fc(512, 1000)
```

标准 torchvision ResNet-18 的 stem 使用 `maxpool`。当前密文验证路径为了先打通
packed 主链路，stem 使用 HE 友好的 `3x3 stride-2 padding-1 average pool`，
并且明文参考路径同步使用同一个 average pool 进行误差比较。

## Parameters

权重默认放在：

```text
Trident/resnet18/pretrained_parameters/resnet18_imagenet/
```

文件命名按 torchvision state_dict 的层名把 `.` 替换为 `_`：

```text
conv1_weight.txt
bn1_weight.txt
bn1_bias.txt
bn1_running_mean.txt
bn1_running_var.txt
layer1_0_conv1_weight.txt
layer1_0_bn1_weight.txt
...
layer2_0_downsample_0_weight.txt
layer2_0_downsample_1_weight.txt
layer2_0_downsample_1_bias.txt
layer2_0_downsample_1_running_mean.txt
layer2_0_downsample_1_running_var.txt
...
fc_weight.txt
fc_bias.txt
```

也兼容 `linear_weight.txt` / `linear_bias.txt`。

如果已有 torchvision 的 `resnet18-f37072fd.pth`，可以直接导出：

```bash
python3 Trident/resnet18/export_torchvision_resnet18_txt.py
```

## Input Data

输入默认读取：

```text
Trident/resnet18/testFile/test_values.txt
Trident/resnet18/testFile/test_label.txt
```

`test_values.txt` 按图片顺序顺序存放预处理后的 ImageNet 张量，每张图片需要
`224 * 224 * 3` 个浮点数，布局与 ResNet20 版本保持一致：channel-first
`C,H,W` 展平。`test_label.txt` 每行或空白分隔存一个 ImageNet label。

如果目录里已有：

```text
testFile/val/ILSVRC2012_val_*.JPEG
testFile/LOC_val_solution.csv
testFile/LOC_synset_mapping.txt
```

可以生成当前 C++ loader 需要的输入文件：

```bash
python3 Trident/resnet18/prepare_imagenet_val_subset.py
```

脚本会按图片编号排序。比如当前 1000 张子集中：

```text
image_id 0   -> ILSVRC2012_val_00000001.JPEG
image_id 999 -> ILSVRC2012_val_00001000.JPEG
```

对应关系会写到 `test_manifest.txt`。如果只想先准备少量图片，可以使用
`--limit N`。

当前配置使用 `logN=21`、`log_slots=20`、`init_p=1`，以容纳 ImageNet stem
之后的 packed tensor。完整密文推理会非常重，建议先只跑单张图片。
