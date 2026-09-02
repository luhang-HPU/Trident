# ResNet20 Poseidon Inference

这个目录实现了基于 Poseidon CKKS 的 CIFAR-10 ResNet20 密文推理流程。代码同时保留了一条明文参考路径，用来在调试时对照密文推理的中间结果和最终分类结果。

## 快速开始

在仓库根目录执行：

```bash
cmake --build Trident/build --target resnet20 -j2
./Trident/build/resnet20/resnet20 START_IMAGE_ID END_IMAGE_ID
```

示例：

```bash
./Trident/build/resnet20/resnet20 0 9
```

只统计完整密态网络、不运行逐层明文参考、中间解密 preview 和最终 logits 解密：

```bash
./Trident/build/resnet20/resnet20 0 0 --inference-only
```

该模式在输入密文和初始 level 对齐完成后开始计时，在密文 FC logits 生成后停止，
日志字段为 `encrypted inference time`。密钥生成、权重/图片读取、输入编码加密和最终
解密均不计入；当前卷积内部按需进行的权重/mask向量构造与CKKS编码仍计入该时间。
普通验证模式仍保留原来的逐层解密和最终预测检查。

注意：图片区间是闭区间，`0 9` 会跑 10 张图片，`0 49` 会跑 50 张图片。当前程序按图片顺序串行执行，不会并行跑多张图片。

## 目录结构

```text
Trident/resnet20/
  resnet20.cpp              程序入口，解析命令行参数
  infer.h/.cpp              推理主流程，编排 ResNet20 的各层执行顺序
  infer_config.h/.cpp       推理配置、路径配置、CKKS 参数、ReLU 参数
  infer_runtime.h/.cpp      Poseidon runtime 初始化，包括 context、keys、encoder、evaluator
  parameter_loader.h/.cpp   读取图片、label、ResNet20 权重
  tensor_cipher.h/.cpp      密文 tensor 封装，保存形状信息和 Ciphertext
  encrypted_ops.h/.cpp      密文算子实现，如卷积、BN、ReLU、bootstrap、add、pool、FC
  encrypted_ops_trace.cpp   带日志的密文算子包装
  plain_cnn.h/.cpp          明文参考实现，用于调试和结果对照
  relu_approx.h/.cpp        ReLU 近似中的 sign 多项式、树结构和系数加载
  cnn.h                     兼容头文件，主要转发 encrypted_ops.h
  test_relu_levels.cpp      ReLU 层级测试
  test_bootstrap_levels.cpp Bootstrap 层级测试
  testFile/                 CIFAR-10 测试图片和 label
  pretrained_parameters/    ResNet20 预训练参数
  relu_param/               ReLU 近似参数
  result/                   推理输出目录
```

## 主执行流程

程序入口在 `resnet20.cpp`：

```cpp
int main(int argc, char **argv)
```

它负责解析 `START_IMAGE_ID`、`END_IMAGE_ID` 和可选的 `--inference-only`，然后调用：

```cpp
ResNet_cifar10_sparse(start_image_id, end_image_id, options);
```

真正的推理流程在 `infer.cpp` 的 `ResNet_cifar10_sparse()` 中：

```text
1. 创建 PoseidonInferPlan
2. 创建 ReluConfig
3. 初始化 PoseidonRuntime
4. 创建 result 目录和输出文件
5. 加载 ResNet20 权重
6. 对每张图片顺序执行：
   1. 读取图片和 label
   2. 构造明文输入 PlainTensor
   3. 构造密文输入 TensorCipher
   4. 执行 stem
   5. 执行 stage1、stage2、stage3
   6. 执行 head
   7. 写每张图片日志、summary 和 status
```

核心循环是：

```cpp
for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
```

因此 `start` 和 `end` 都会被执行。

## ResNet20 网络结构

网络编排集中在 `infer.cpp`，分为三部分。

### Stem

函数：

```cpp
run_stem(...)
```

执行：

```text
conv -> batch_norm -> relu
```

### Residual Block

函数：

```cpp
run_residual_block(...)
```

执行：

```text
shortcut = input

branch:
  conv1 -> bn1 -> bootstrap -> relu
  conv2 -> bn2

如果是 stage2/stage3 的第一个 block：
  shortcut -> downsample

branch + shortcut -> bootstrap -> relu
```

stage 配置在 `infer_config.cpp`：

```cpp
plan.stages = {
    {"stage1", 16, 3, 1},
    {"stage2", 32, 3, 2},
    {"stage3", 64, 3, 2},
};
```

含义分别是：

```text
name, out_channels, block_count, first_block_stride
```

当前 bootstrap 是全量执行，不按 stage 使用不同的 bootstrap slot 数，因此 stage 配置里不包含 bootstrap log slots。

### Head

函数：

```cpp
run_head(...)
```

执行：

```text
average_pool -> fully_connected -> argmax
```

最终会输出密文路径解密后的 logits、密文预测 label、明文参考 logits、明文参考预测 label。

## 密文路径和明文参考路径

每张图片推理时维护一个 `InferenceState`：

```cpp
struct InferenceState
{
    TensorCipher cipher;
    PlainTensor plain;
    size_t conv_idx = 0;
    size_t bn_idx = 0;
    int logical_layer = 1;
};
```

其中：

```text
cipher        当前密文 tensor
plain         当前明文参考 tensor
conv_idx      当前使用到第几个卷积权重
bn_idx        当前使用到第几个 BN 参数
logical_layer 日志中的逻辑层编号
```

密文路径调用 `encrypted_ops.cpp` 中的算子，明文参考路径调用 `plain_cnn.cpp` 中的算子。比如在 stem 中：

```text
密文：multiplexed_convolution_print(...)
明文：plain_convolution(...)
```

再比如 ReLU：

```text
密文：approx_relu_print(...)
明文：plain_relu_reference(...)
```

明文参考路径不是用于最终密文计算，只用于验证和对照。

## 关键数据结构

### TensorCipher

定义在 `tensor_cipher.h`。

`TensorCipher` 是密文 tensor 的封装，保存：

```text
logn
k, h, w, c, t, p
poseidon::Ciphertext
```

其中 `h/w/c` 是形状信息，`cipher()` 返回真正参与同态计算的密文。

### PlainTensor

定义在 `plain_cnn.h`。

`PlainTensor` 是明文 tensor 的封装：

```cpp
struct PlainTensor
{
    int h;
    int w;
    int c;
    std::vector<double> values;
};
```

数据按 `channel -> row -> col` 的顺序访问：

```cpp
tensor.at(channel, row, col)
```

### PoseidonRuntime

定义在 `infer_runtime.h`。

它把推理过程中常用的 Poseidon 对象集中放在一起：

```text
context
evaluator
encoder
public_key / secret_key
relin_keys / galois_keys
encryptor / decryptor
bootstrap_config
scale
slot_count
```

创建入口是：

```cpp
PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan);
```

## CPU 模数链与层数预算

CPU 推理现在使用 31 个 Q 模数：

```text
Q[0]       : 1 × 45 bit，ModRaise 的 q0
Q[1..16]   : 16 × 40 bit，应用计算层（scale = 2^40）
Q[17..30]  : 14 × 45 bit，14-level Bootstrap（scale = 2^45）
P          : 1 × 51 bit，KeySwitch 特殊模数
```

`log_message_ratio = 5`，因此 Bootstrap 入口目标 scale 为
`2^(45-5) = 2^40`，与应用计算 scale 直接匹配。KeySwitch 使用的 P
不是计算/自举 Q 链的一部分，暂时保留 51 bit。

Bootstrap 的内部多项式 scale 与输出 scale 分开配置：

```cpp
bootstrap_config.scaling_log = 45;         // EvalMod 内部工作 scale
bootstrap_config.output_scaling_log = 40;  // S2C 输出给网络的 scale
```

输出 scale 会融合进 SlotToCoeff 系数，不通过事后改写 ciphertext scale，
也不会额外消耗 level。

对应关系是：

```text
完整链 level 30
    Bootstrap 消耗 14 level
Bootstrap 输出 level 16
    ReLU 消耗 14 level
ReLU 输出 level 2
    卷积消耗 2 level
下一次 Bootstrap 输入 level 0
```

网络开头在第一次 Bootstrap 前还多一个 stem 卷积，所以初始密文对齐到
level 18：

```text
level 18 --stem conv(2)--> 16 --ReLU(14)--> 2
         --first block conv(2)--> 0 --Bootstrap(14)--> 16
```

模数链在 `infer_config.cpp` 的 `logq_chain()` 中设置。推理使用
`EvaluatorCkksBase::bootstrap(..., BootstrapConfig)`；参数在
`infer_runtime.cpp` 中设置。运行日志会打印并检查：

```text
convolution level_consumption=2
relu level_consumption=14
bootstrap level_consumption=14
batchnorm level_consumption=0
```

任何算子的实际消耗与预算不一致时，程序会立即报错，避免在链长度不足时继续
产生无效密文。

### ModelWeights

定义在 `parameter_loader.h`。

包含：

```text
linear_weight
linear_bias
conv_weight
bn_bias
bn_running_mean
bn_running_var
bn_weight
```

加载入口是：

```cpp
ModelWeights load_resnet20_parameters();
```

## ReLU 近似

ReLU 的密文实现不是直接比较大小，而是通过近似 sign 多项式实现。

默认配置在 `infer_config.cpp`：

```cpp
relu_config.comp_no = 3;
relu_config.deg = {15, 15, 27};
relu_config.alpha = 13;
relu_config.scaled_val = 1.7;
```

`default_relu_config()` 会根据 `deg` 构造多项式求值所需的 `Tree`：

```cpp
Tree tr(EvalType::OddBaby);
upgrade_oddbaby(degree, tr);
```

密文 ReLU 主流程：

```text
relu(...)
  -> approximate_sign(...)
  -> 生成 mask
  -> input * mask
```

`approximate_sign()` 定义在 `relu_approx.cpp`，它会从 `relu_param/` 读取对应多项式系数。

明文参考 ReLU 是普通 ReLU：

```cpp
max(0.0, x)
```

对应函数：

```cpp
plain_relu_reference(...)
```

## 输出文件

输出目录：

```text
Trident/resnet20/result/
```

每次运行会根据起止图片 ID 和时间戳生成几类文件。

### 每张图片详细日志

格式：

```text
resnet20_cifar10_image<image_id>_<timestamp>.txt
```

包含该图片每一层的密文状态、scale、level、部分解密 preview、最终 logits 和预测结果。

### Summary 文件

格式：

```text
resnet20_cifar10_label_<start>_<end>_<timestamp>.txt
```

每张图片完成后追加一行：

```text
image_id: ..., image label: ..., predicted label: ..., plain predicted label: ...
```

最后追加总耗时。

### Status 文件

格式：

```text
resnet20_cifar10_status_<start>_<end>_<timestamp>.txt
```

这个文件用于观察长时间运行的进度。它会在每张图片开始和结束时立刻 flush。

内容类似：

```text
run_start: start_image_id=0, end_image_id=49, run_timestamp=...
image_start: 0
image_done: 0, image label: ..., predicted label: ..., plain predicted label: ...
image_start: 1
...
run_done: total_time_ms=...
```

如果程序还在跑，summary 可能还没写满，但 status 文件可以看到当前跑到哪张图。

## 重要配置

主要配置在 `infer_config.h` 和 `infer_config.cpp`。

### 图片和模型

```cpp
constexpr std::size_t kResNet20LayerNum = 20;
constexpr int kResNet20EndNum = 2;
constexpr const char *kResNet20ParameterDir = "resnet20_new";
constexpr const char *kResNet20ResultPrefix = "resnet20_cifar10";
```

### CKKS 推理参数

```cpp
plan.boundary = 40.0;
plan.logN = 16;
plan.log_slots = 15;
plan.init_p = 8;
plan.log_scale = 40;
plan.remaining_level = 16;
plan.boot_level = 14;
```

### Bootstrap 开关

```cpp
constexpr bool kEnableBootstrap = true;
```

如果设成 `false`，`maybe_bootstrap()` 会跳过 bootstrap，并在日志中写：

```text
bootstrap stage ... skipped
```

通常不要关闭，除非你专门调试层级消耗。

### 明文中间结果日志

```cpp
constexpr bool kLogPlainIntermediate = false;
```

设成 `true` 后，每张图片日志会额外输出明文参考路径的中间 tensor preview，例如：

```text
plain input
plain conv output
plain batchnorm output
plain relu output
plain add output
plain average pool output
```

这个开关只控制日志打印，不影响明文参考路径是否计算。平时建议保持 `false`，因为打开后日志会明显变大。

## 参数和数据读取

图片数据来自：

```text
testFile/test_values.txt
testFile/test_label.txt
```

权重数据来自：

```text
pretrained_parameters/resnet20_new/
```

读取入口：

```cpp
read_image_slots(...)
read_image_label(...)
load_resnet20_parameters()
```

`read_image_slots()` 会做两件额外处理：

```text
1. 把一张 32*32*3 图片放入 CKKS slots
2. 按 boundary 做缩放：slot /= boundary
```

默认 `boundary = 40.0`。

## 测试程序

### ReLU 测试

```bash
cmake --build Trident/build --target resnet20_test_relu -j2
./Trident/build/resnet20/resnet20_test_relu
```

用于观察 ReLU 近似过程中的 level、scale 和解密 preview。

### Bootstrap 测试

```bash
cmake --build Trident/build --target resnet20_test_bootstrap -j2
./Trident/build/resnet20/resnet20_test_bootstrap
```

用于单独检查 bootstrap 的层级变化和输出状态。

## 从 ResNet18 移植的计算优化

ResNet20 的特征始终装在一个 `TensorCipher` 中，没有 ResNet18 的多 input-pack
结构，因此不能照搬“跨 pack 后再通道归约”或“多个输出矩阵共享 BSGS baby
rotation”。当前移植的是与 packing 无关的线性融合累加：

- 3×3 卷积：同一个输出组的9个 kernel PMult在高scale下用
  `multiply_plain_accumulate`累加，只rescale一次；所有输出通道的放置与折叠BN
  scale也先融合累加，再统一rescale一次。
- Downsample shortcut：所有mask PMult和rotation先在同一level/scale下相加，最后
  统一rescale。
- Global average pool：16个输出选择项统一融合累加和rescale。
- FC：73条对角线PMult统一融合累加和rescale。
- rotation-add等已知同level/scale的线性归约直接使用原地`add`，不再进入动态
  level/scale对齐路径。

这些改动不改变乘法深度：卷积仍消耗2个level，downsample、pool和FC仍各消耗1个
level。完整网络上述线性算子的rescale调用上界由2267次降为185次，减少2082次；
每层日志中的`lazy_rescale`会给出该层优化前后的操作数。

ResNet20当前Bootstrap本来就输出`chain_index=16`，复合ReLU恰好消耗14个level并
输出到2，因此不需要ResNet18的“Bootstrap输出20再裁到16”优化。Bootstrap明文
矩阵的编码和融合累加也没有在本次修改范围内。

旧日志`resnet20_cifar10_image0_20260822_151823.txt`的单图阶段时间约为：Bootstrap
4,344,630 ms、ReLU 192,943 ms、卷积143,129 ms，其余线性层约9,600 ms。也就是说
Bootstrap约占92.5%，本次优化针对的是剩余约3.2%的卷积/线性热区；完整端到端收益
需要用新的单图日志实测，不能按rescale数量线性估算。

## 常见问题

### 为什么跑 50 张图片却只看到 10 个结果？

当前程序按图片串行运行，不是并行运行。只有某张图片完整跑完后，它的 summary 行才会写入。程序还在运行时，summary 里只看到已经完成的图片是正常的。

可以看 status 文件确认进度：

```text
result/resnet20_cifar10_status_<start>_<end>_<timestamp>.txt
```

### 为什么 `0 50` 不是 50 张？

因为区间是闭区间：

```cpp
for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
```

所以：

```text
0 49 -> 50 张
0 50 -> 51 张
```

### `multiplexed_convolution` 是并行卷积吗？

不是。这里的 `multiplexed` 表示数据在 CKKS slots 中的打包和旋转计算方式，不表示多张图片并行运行。

### 密文结果和明文结果在哪里对照？

最终结果会写在每张图片日志中：

```text
logits:
predicted label:
plain logits:
plain predicted label:
```

如果需要看中间层明文参考，把 `kLogPlainIntermediate` 改成 `true` 后重新编译运行。

## 阅读代码建议

建议按这个顺序读：

```text
1. resnet20.cpp
2. infer_config.h / infer_config.cpp
3. infer_runtime.h / infer_runtime.cpp
4. parameter_loader.h / parameter_loader.cpp
5. infer.cpp
6. tensor_cipher.h / tensor_cipher.cpp
7. encrypted_ops.h / encrypted_ops.cpp
8. encrypted_ops_trace.cpp
9. plain_cnn.h / plain_cnn.cpp
10. relu_approx.h / relu_approx.cpp
```

如果只想理解整体流程，重点看 `resnet20.cpp` 和 `infer.cpp`。如果要调试某个同态算子，再进入 `encrypted_ops.cpp`。如果要对照密文误差，再看 `plain_cnn.cpp` 和 `kLogPlainIntermediate`。
