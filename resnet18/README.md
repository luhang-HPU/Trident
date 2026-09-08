# ResNet18 ImageNet Poseidon Inference

这个目录实现 ImageNet 版 ResNet-18 的 Poseidon CKKS 密态推理，输入尺寸为
`224x224x3`，输出为 `1000` 类 logits。

完整的密文布局、同态算子、Bootstrap、模数链和逐层执行说明见
[`ENCRYPTED_INFERENCE.md`](ENCRYPTED_INFERENCE.md)。

## Build

```bash
cmake -S Trident -B Trident/build -DRESNET18=ON
cmake --build Trident/build --target resnet18 -j2
cmake --build Trident/build --target resnet18_plain -j2
```

当前 `resnet18` 是密文入口。程序把输入直接重排并加密为首层 `7×7×3=147`
个 im2col patch 密文，供 stem 卷积使用：

```bash
./Trident/build/resnet18/resnet18 START_IMAGE_ID END_IMAGE_ID
```

只运行密态网络、不做逐层明文参考和解密检查：

```bash
RESNET18_THREADS=8 \
./Trident/build/resnet18/resnet18 0 0 4 \
  --inference-only \
  --conv-plaintext-cache-mb=2048
```

`--conv-plaintext-cache-mb` 控制卷积编码明文跨层/跨图片复用的 LRU 常驻上限，默认
2048 MiB；设为 0 时仍会按需编码当前操作的明文，但不跨操作保留。

当前密文入口会完成整张 ResNet-18 网络：

```text
ImageNet input -> 147 ciphertext im2col patches
-> conv1 + bn + polynomial relu + average pool
-> layer1 + layer2 + layer3 + layer4
-> global average pool -> encrypted fc(512, 1000)
-> decrypt logits -> argmax
```

默认验证模式会在各层同步计算明文参考结果，记录密文明文误差、模数链、耗时、
真实标签和最终预测标签。`--inference-only` 会保留最终加密 logits，但跳过明文网络、
中间 decrypt/decode、Bootstrap 自检以及最终解密预测。密态推理日志写入
`resnet18/result/`。

FC 的 1511 条 BSGS 对角明文和 bias 会在进入图片循环前编码一次并复用，约占
2.27 GiB。卷积使用跨 input-pack lazy rescale：同一输出通道的所有 kernel 和 input
pack 贡献先在相同 level/scale 下完成 rotation-add，再统一执行一次 kernel rescale，
最后只做一次输出选择和 rescale。若全部使用 compact 路径，完整网络的 multiplexed
卷积 rescale 上界由原始 103424 次降为 9472 次；默认融合 BSGS 又把 Layer3/4 的
7680 次替换为 35 个 pack-matrix rescale，使当前默认上界为 1827 次。compact 层保持“kernel
累加 1 level + 输出选择 1 level”的两层深度，融合 BSGS 层只消耗一层深度。
卷积 kernel 累加调用 Poseidon 的融合 `multiply_plain_accumulate`，只保留一个 RNS
多项式 scratch，不再为每项构造完整临时密文。Stem 的 147 个 im2col 项也按输出
通道 lazy 累加后统一 rescale，使首层 rescale 上界从 9408 次降为 64 次；常数权重
直接在各 Q 模数下生成 residue，避免 9408 次通用 CKKS scalar encode。

compact 卷积现在先跨全部 input packs 累加，再统一执行局部通道归约和输出位置旋转。
例如 Layer1 的这部分 rotation 上界由 2048 降到 256，Layer2 stride-1 由 3072
降到 768；因此 Layer1/2 默认保留 compact 路径。Layer3/4 首块的 stride-2 主分支
`3×3`、projection shortcut `1×1`，以及 Layer3/4 的 3 个 stride-1 `3×3` 默认走
融合稀疏对角 BSGS。每条 BSGS 路径把空间卷积、通道混合和 BN 乘法缩放合成一个 slot 线性
变换。同一个 input/output pack 对只做一次 BSGS 和一次 rescale；一个卷积层可能包含
多个 pack 对，因此总 rescale 操作数等于日志中的 `matrices`，但所有 pack 对并行处于
同一 level，整层乘法深度由 2 level 降为 1 level。

同一个 input pack、同一个 `n1` 的多个输出矩阵会共享 baby rotations，不再让每个
output pack 重复旋转输入：

| 路径（单层） | BSGS 明文乘法 | sharing 前 rotation 上界 | sharing 后上界 |
| --- | ---: | ---: | ---: |
| Layer2 stride-2 `3×3`（可选） | 7776 | 1760 | 1352 |
| Layer2 projection `1×1`（可选） | 2400 | 928 | 712 |
| Layer3 stride-2 `3×3` / projection | 8664 / 2904 | 912 / 544 | 788 / 460 |
| Layer4 stride-2 `3×3` / projection | 9126 / 3174 | 462 / 264 | 462 / 264 |
| Layer3 stride-1 `3×3` | 11532 | 672 | 610 |
| Layer4 stride-1 `3×3` | 11907 | 294 | 294 |

代价是增加明文乘法和编码对角的峰值内存。日志会逐层给出 `matrices`、
`encoded_bytes` 和准备时间。准备过程不计入 `encrypted_inference_time_ms`。为避免
10 万余条大明文跨层累计导致 OOM，BSGS 计划默认在该层计算完成后释放；如需多图片
复用，可用 `RESNET18_FUSED_BSGS_CACHE_MB` 设置 LRU 常驻上限，例如 256 GiB：

```bash
RESNET18_FUSED_BSGS_CACHE_MB=262144 \
  ./Trident/build/resnet18/resnet18 0 1 4 --inference-only
```

只有完整计划不大于上限时才会缓存，实际状态见日志的 `cache_retained`、
`cache_resident_bytes` 和 `cache_limit_bytes`。

单线程推理时，可以单独用多线程准备 BSGS 明文而不改变密态算子线程数：

```bash
RESNET18_THREADS=1 RESNET18_PREP_THREADS=8 \
  ./Trident/build/resnet18/resnet18 0 0 4 --inference-only
```

所有 BSGS baby/giant rotation keys 仍在第一张图片前一次性生成。可用下面的变量回退
旧卷积，做同机 A/B 对比：

```bash
# 关闭所有融合卷积 BSGS
RESNET18_FUSED_CONV_BSGS=0 ./Trident/build/resnet18/resnet18 0 0 4 --inference-only

# 也可分别关闭 transition、Layer3 或 Layer4
RESNET18_TRANSITION_BSGS=0 RESNET18_LAYER3_BSGS=0 RESNET18_LAYER4_BSGS=0 \
  ./Trident/build/resnet18/resnet18 0 0 4 --inference-only

# Layer2 transition 默认使用优化后的 compact；只建议用此开关做 A/B
RESNET18_LAYER2_TRANSITION_BSGS=1 \
  ./Trident/build/resnet18/resnet18 0 0 4 --inference-only
```

中间 Bootstrap 返回后默认直接降到 `chain_index=16` 再执行恰好消耗 14 level 的
ReLU，避免 ReLU 在用不到的 4 个高层 Q 模数上做 NTT/乘法。最终 Layer4 输出为了
兼容现有 global-average-pool 和 FC 保留完整 Bootstrap 输出。可用
`RESNET18_POST_BOOTSTRAP_LEVEL=20` 回退旧行为。stem 的 `1/9` 和分类头的
`20/49` 已分别融合进已有选择 mask，不再单独做 scalar PMult + rescale；分类头仍做
一次纯 modulus drop，以保持 FC 预编码明文所需的输入 level。

当前没有强行启用 Winograd：现有 SIMD 卷积一个 3×3 核只需 9 个空间分量，而标准
`F(2×2,3×3)` 需要 16 个变换域分量，并额外增加输入/输出变换和 level；在不改变
全网 packing 的前提下会回退性能。融合 BSGS 已把目标层的空间与通道线性变换整体
合并。

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
3x3 stride-2 average pool
layer1: 2 BasicBlock, 64 channels
layer2: 2 BasicBlock, 128 channels, first block stride 2 + projection shortcut
layer3: 2 BasicBlock, 256 channels, first block stride 2 + projection shortcut
layer4: 2 BasicBlock, 512 channels, first block stride 2 + projection shortcut
global average pool -> fc(512, 1000)
```

标准 torchvision ResNet-18 的 stem 使用 `maxpool`。密态路径使用 HE 友好的
`3x3 stride-2 padding-1 average pool`，明文参考路径默认使用相同的 average pool
进行逐层误差比较。`resnet18_plain` 可追加 `maxpool` 参数，用于单独对照标准 stem。

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

当前配置使用 `logN=16`、`log_slots=15`、`init_p=8`。一张输入包含 150528
个数，因此入口按通道拆成 6 个密文；进入 stem 后再转换为通道组和 multiplexed
packed 布局。完整密文推理计算量很大，建议先只跑单张图片。
