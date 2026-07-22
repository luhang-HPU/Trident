# ResNet-50 ImageNet 同态加密推理运行说明

本目录实现基于 Poseidon CKKS 的 ResNet-50 ImageNet 推理，包含卷积、批归一化、多项式 ReLU、残差连接、全局平均池化和全连接层。

提供两个程序：

- `resnet50`：密文推理程序，支持完整同态模式和 mock 调试模式。
- `resnet50_plain`：明文参考程序，用于快速检查输入、参数和中间结果。

密态推理的数据布局、算子和 bootstrap/ReLU 实现见 [ResNet-50 密态推理实现详解](ENCRYPTED_INFERENCE.md)。

## 1. 运行前准备

以下命令均从 Poseidon 仓库根目录执行。仓库可以放在任意位置，文档中的路径全部为相对于仓库根目录的路径。

需要满足：

- Linux、CMake 3.12 或更高版本、支持 C++20 的编译器。
- GMP、pthread 和 OpenMP 可用。
- Poseidon 动态库已经编译为 `build/libposeidon_shared.so`。
- ResNet-50 权重文本、测试输入和标签已经准备好。

如果 Poseidon 尚未编译：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target poseidon_shared -j4
```

## 2. 检查权重和测试数据

正式运行至少需要以下文件：

```text
Trident/resnet50/
├── pretrained_parameters/
│   └── resnet50_imagenet/
│       ├── conv1_weight.txt
│       ├── bn1_*.txt
│       ├── layer*_*.txt
│       └── fc_*.txt
├── relu_param/
│   └── d13.txt
└── testFile/
    ├── test_values.txt
    └── test_label.txt
```

`test_values.txt` 中每张图片包含 `3 × 224 × 224 = 150528` 个连续数值，`test_label.txt` 中的标签取值范围为 `0–999`。当前输入文件包含 30 张图片，因此当前可用图片 ID 为 `0–29`。

程序优先读取本目录的 `relu_param/`；如果该目录不存在，则回退到 `Trident/resnet18/relu_param/`。

### 可选：重新导出 torchvision 权重

已有 `pretrained_parameters/resnet50_imagenet/` 时不需要执行本步骤。重新导出需要 Python 和 PyTorch：

```bash
python3 Trident/resnet50/export_torchvision_resnet50_txt.py \
  --input Trident/resnet50/pretrained_parameters/resnet50-11ad3fa6.pth
```

不指定 `--input` 时，脚本会在 `pretrained_parameters/` 中查找常见的 torchvision ResNet-50 `.pth` 文件。

## 3. 编译 ResNet-50

以下配置只启用 ResNet-50，避免编译 Trident 中其他应用和测试：

```bash
cmake -S Trident -B Trident/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-I$(pwd)/src -L$(pwd)/build -Wl,-rpath,$(pwd)/build" \
  -DBuild_GoogleTest=OFF \
  -DPIR=OFF \
  -DAPSI=OFF \
  -DLR_TRAIN=OFF \
  -DHEARTSTUDY=OFF \
  -DKNN=OFF \
  -DMNIST=OFF \
  -DRESNET20=OFF \
  -DRESNET18=OFF \
  -DRESNET50=ON

cmake --build Trident/build --target resnet50 resnet50_plain -j4
```

生成的程序位于：

```text
Trident/build/resnet50/resnet50
Trident/build/resnet50/resnet50_plain
```

## 4. 先运行明文参考程序

建议先用一张图片检查权重和输入数据：

```bash
./Trident/build/resnet50/resnet50_plain 0 0
```

命令格式：

```text
resnet50_plain START_IMAGE_ID END_IMAGE_ID [avgpool|maxpool] [relu|polyrelu]
```

图片区间包含起点和终点。默认使用 `avgpool polyrelu`，这也是与当前密文路径进行中间结果对照时应使用的配置。

示例：

```bash
./Trident/build/resnet50/resnet50_plain 0 2
./Trident/build/resnet50/resnet50_plain 0 0 avgpool relu
```

第一条命令运行图片 0、1、2；第二条命令使用标准 ReLU 作为明文基线。

## 5. 运行完整密文推理

完整模式会执行真实的同态 ReLU 和 bootstrap。该模式计算量和内存占用较大，建议先运行一张图片：

```bash
RESNET50_THREADS=8 ./Trident/build/resnet50/resnet50 0 0
```

命令格式：

```text
resnet50 START_IMAGE_ID END_IMAGE_ID
```

图片区间同样包含起点和终点。例如下面的命令会依次运行图片 10、11、12：

```bash
RESNET50_THREADS=8 ./Trident/build/resnet50/resnet50 10 12
```

如果系统找不到 `libposeidon_shared.so`，可以显式设置：

```bash
export LD_LIBRARY_PATH="$(pwd)/build:${LD_LIBRARY_PATH:-}"
```

## 6. Mock 调试模式

Mock 模式会在非线性刷新位置通过明文参考值重新生成密文，适合检查数据布局、线性层和整体执行流程：

```bash
RESNET50_MOCK_RELU=1 \
RESNET50_MOCK_BOOTSTRAP=1 \
RESNET50_THREADS=8 \
./Trident/build/resnet50/resnet50 0 0
```

也可以只启用其中一个变量。Mock 模式不是完整同态推理，其耗时和误差不能作为正式性能或精度结果。

恢复完整模式时清除变量：

```bash
unset RESNET50_MOCK_RELU RESNET50_MOCK_BOOTSTRAP
```

## 7. 并行线程数

通过 `RESNET50_THREADS` 控制并行度：

```bash
RESNET50_THREADS=1 ./Trident/build/resnet50/resnet50 0 0
RESNET50_THREADS=8 ./Trident/build/resnet50/resnet50 0 0
```

未设置时，程序根据硬件线程数自动选择，最多使用 8 个线程。内存不足时可将线程数降低到 1、2 或 4。

## 8. 输出文件

所有日志写入 `Trident/resnet50/result/`。

密文推理日志：

```text
resnet50_imagenet_run_START_END_TIMESTAMP.txt
```

明文推理日志：

```text
resnet50_plain_label_START_END_TIMESTAMP.txt
resnet50_plain_imageIMAGE_ID_TIMESTAMP.txt
```

密文日志中建议重点检查：

- `[compare]`：各层明文与密文的最大、平均绝对误差。
- `[logit-decision]`：真实标签、明文预测、密文预测及二者是否一致。
- `head logits max_abs_error`：最终 logits 最大绝对误差。
- `image_done`：单张图片完成标记和汇总。
- `run_done`：整个图片区间完成标记和总耗时。
- `[memory]`、`[operation]`：内存和算子耗时信息。

## 9. 常见问题

### `failed to open file: ...pretrained_parameters...`

权重文本缺失或目录名不正确。确认权重位于 `Trident/resnet50/pretrained_parameters/resnet50_imagenet/`。

### `failed to read ImageNet input values`

图片 ID 超出 `test_values.txt` 中实际包含的图片数量，或输入文件不完整。当前数据应使用 ID `0–29`。

### `libposeidon_shared.so: cannot open shared object file`

先确认 `build/libposeidon_shared.so` 存在，再按第 5 节设置 `LD_LIBRARY_PATH`，或者重新执行第 3 节的 CMake 配置。

### 运行时间过长或内存不足

先使用单张图片和 mock 模式检查流程，再运行完整模式；同时降低 `RESNET50_THREADS`。完整密文 ResNet-50 本身就是高计算量、高内存任务。

### 明文和密文结果无法对齐

确认明文参考使用默认的 `avgpool polyrelu`，并检查是否意外保留了 `RESNET50_MOCK_RELU` 或 `RESNET50_MOCK_BOOTSTRAP` 环境变量。
