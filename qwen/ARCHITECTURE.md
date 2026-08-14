# Qwen2.5-0.5B CPU 明文推理架构

本文档说明 `Trident/qwen` 中 C++ CPU 明文推理的完整数据流、张量形状、
算子边界和 KV Cache 生成流程。当前实现使用官方 Qwen2.5-0.5B Base
checkpoint，并已与 Hugging Face Transformers 完成逐层数值验证。

## 1. 整体数据流

```text
Token IDs [T]
   |
   v
Embedding Lookup
   |
   v
Hidden States [T, 896]
   |
   +--> Decoder Layer 0
   +--> Decoder Layer 1
   |        ...
   +--> Decoder Layer 23
   |
   v
Final RMSNorm [T, 896]
   |
   v
取最后一个 Token [1, 896]
   |
   v
LM Head: 896 -> 151936
   |
   v
Logits [1, 151936]
   |
   v
Argmax / Top-K
   |
   v
Next Token
```

其中 `T` 表示本次输入的 token 数量。当前 C++ 推理核心支持单序列推理，
即 `batch_size=1`。

## 2. 模型配置

当前使用的官方 checkpoint 配置如下：

| 参数 | 数值 |
|---|---:|
| 模型 | Qwen2.5-0.5B Base |
| Decoder 层数 | 24 |
| Hidden size | 896 |
| MLP intermediate size | 4864 |
| Query heads | 14 |
| KV heads | 2 |
| Head dimension | 64 |
| GQA 分组大小 | 7 |
| Vocabulary size | 151936 |
| 最大序列长度 | 32768 |
| RMSNorm epsilon | `1e-6` |
| RoPE theta | `1000000` |
| Checkpoint dtype | BF16 |
| Sliding window | 关闭 |
| Embedding/LM Head 权重共享 | 开启 |

GQA 分组大小为：

```text
query_group_size = num_attention_heads / num_key_value_heads
                 = 14 / 2
                 = 7
```

因此每 7 个 Query Head 共享一个 Key/Value Head。

## 3. 权重加载

C++ 首先读取：

```text
config.json
model.safetensors
```

`SafeTensorStore` 支持单文件和分片 checkpoint，并支持以下权重类型：

```text
F64
F32
F16
BF16
```

官方 Qwen2.5-0.5B 权重是 BF16。当前明文基准会在加载时将 BF16 转换为
`double`，之后所有主要 C++ 算子都使用 `Tensor<double>`。

需要加载的主要权重包括：

```text
model.embed_tokens.weight
model.layers.N.input_layernorm.weight
model.layers.N.self_attn.q_proj.weight/bias
model.layers.N.self_attn.k_proj.weight/bias
model.layers.N.self_attn.v_proj.weight/bias
model.layers.N.self_attn.o_proj.weight
model.layers.N.post_attention_layernorm.weight
model.layers.N.mlp.gate_proj.weight
model.layers.N.mlp.up_proj.weight
model.layers.N.mlp.down_proj.weight
model.norm.weight
```

该模型启用了 `tie_word_embeddings`，因此 LM Head 直接复用
`model.embed_tokens.weight`。

## 4. Token Embedding

输入是一维 token ID 数组：

```text
token_ids: [T]
```

Embedding 权重形状：

```text
[151936, 896]
```

对每个 token ID 从 Embedding 表中取出对应的一行：

```text
[T] -> [T, 896]
```

Embedding Lookup 仅进行索引和内存复制，不进行矩阵乘法。

当前 C++ 核心不实现 tokenizer。文本到 token ID 的转换由 Hugging Face
tokenizer 或其他上层组件完成。

## 5. Decoder Layer

每个 Decoder Layer 的完整数据流如下：

```text
input [T, 896]
   |
   v
Input RMSNorm
   |
   v
Q/K/V Linear Projection
   |
   v
Split Heads
   |
   v
RoPE(Q, K)
   |
   v
Causal GQA Attention
   |
   v
Merge Heads + Output Linear
   |
   v
Residual Add
   |
   v
Post-Attention RMSNorm
   |
   +--> Gate Linear --\
   |                  +--> SiLU(Gate) * Up
   +--> Up Linear ----/
                      |
                      v
                 Down Linear
                      |
                      v
                 Residual Add
                      |
                      v
              layer output [T, 896]
```

该结构重复执行 24 次，每层使用不同权重。

## 6. RMSNorm

对每个 token 的 896 个 hidden feature 计算：

```text
variance = mean(x^2)
inverse_rms = 1 / sqrt(variance + epsilon)
output = x * inverse_rms * weight
```

输入输出形状不变：

```text
[T, 896] -> [T, 896]
```

每个 Decoder Layer 包含两个 RMSNorm：

```text
input_layernorm
post_attention_layernorm
```

24 层之后还有一个 Final RMSNorm。

RMSNorm 涉及的基础操作：

```text
逐元素平方
按 hidden 维求和/平均
加 epsilon
平方根
倒数
逐元素乘法
```

## 7. Q/K/V 投影

归一化后的 hidden states 分别乘以 Q、K、V 权重：

```text
Q = X * Wq^T + bq
K = X * Wk^T + bk
V = X * Wv^T + bv
```

具体形状如下：

```text
X:  [T, 896]
Wq: [896, 896]  -> Q: [T, 896]
Wk: [128, 896]  -> K: [T, 128]
Wv: [128, 896]  -> V: [T, 128]
```

然后将最后一维拆成 Attention Head：

```text
Q: [T, 896] -> [T, 14, 64]
K: [T, 128] -> [T,  2, 64]
V: [T, 128] -> [T,  2, 64]
```

## 8. RoPE 位置编码

RoPE 只应用于 Q 和 K，不应用于 V：

```text
Q [T, 14, 64] -> RoPE(Q)
K [T,  2, 64] -> RoPE(K)
```

当前实现使用 Qwen split-half 旋转方式。每个 64 维 Head 被分成两个
32 维部分：

```text
x1' = x1 * cos(angle) - x2 * sin(angle)
x2' = x2 * cos(angle) + x1 * sin(angle)
```

其中：

```text
frequency[i] = theta^(-2i / head_dim)
angle = position * frequency[i]
```

Prefill 时 `position` 从 0 开始。Decode 时从当前 KV Cache 长度继续，
保证新 token 使用正确的位置。

## 9. Causal GQA Attention

每个 Query Head 使用以下 KV Head：

```text
kv_head = query_head / 7
```

Attention 计算为：

```text
score = Q * K^T / sqrt(64)
probability = softmax(score)
attention = probability * V
```

Softmax 使用数值稳定形式：

```text
softmax(x_i) = exp(x_i - max(x)) / sum(exp(x_j - max(x)))
```

因果约束通过可见 token 数量隐式实现：

```text
token 0 只能看到 token 0
token 1 能看到 token 0..1
token 2 能看到 token 0..2
...
```

因此当前实现不需要显式创建完整的 Causal Mask 矩阵。

Attention 输出形状：

```text
[T, 14, 64]
```

合并 Head：

```text
[T, 14, 64] -> [T, 896]
```

再执行输出投影：

```text
attention_output = attention * Wo^T
[T, 896] -> [T, 896]
```

最后执行 Attention 残差连接：

```text
post_attention = input + attention_output
```

## 10. MLP 与 SwiGLU

Attention 残差结果先经过 Post-Attention RMSNorm，然后执行两个并行投影：

```text
gate = X * Wgate^T
up   = X * Wup^T
```

形状为：

```text
X:    [T, 896]
gate: [T, 4864]
up:   [T, 4864]
```

SiLU 激活：

```text
SiLU(x) = x / (1 + exp(-x))
```

SwiGLU：

```text
activated = SiLU(gate) * up
```

Down Projection 将 intermediate size 降回 hidden size：

```text
[T, 4864] -> [T, 896]
```

最后执行 MLP 残差连接：

```text
layer_output = post_attention + mlp_output
```

## 11. Final RMSNorm 与 LM Head

24 个 Decoder Layer 执行完成后：

```text
final_hidden = FinalRMSNorm(hidden)
```

如果需要所有位置的 logits：

```text
[T, 896] -> [T, 151936]
```

生成时只计算最后一个 token：

```text
last_hidden: [1, 896]
lm_head:     [151936, 896]
logits:      [1, 151936]
```

由于 Embedding 和 LM Head 权重共享，实际计算相当于：

```text
logits = last_hidden * embedding_weight^T
```

## 12. Prefill

生成的第一次前向处理完整 Prompt：

```text
Prompt Token IDs [T]
   |
   v
24 层完整前向
   |
   +--> 每层保存 K Cache [T, 2, 64]
   +--> 每层保存 V Cache [T, 2, 64]
   |
   v
最后一个位置的 Logits [1, 151936]
```

这一步称为 Prefill。

## 13. KV Cache Decode

选择下一个 token 后，不再重新计算完整 Prompt，只输入一个新 token：

```text
New Token [1]
   |
   v
Embedding [1, 896]
   |
   v
每层生成新的 Q/K/V
   |
   +--> 新 K 追加到历史 K Cache
   +--> 新 V 追加到历史 V Cache
   |
   v
新 Q 对全部历史 K/V 做 Attention
   |
   v
Next Logits [1, 151936]
```

假设当前 Cache 长度为 `S`：

```text
Q:         [1, 14, 64]
K Cache:   [S,  2, 64]
V Cache:   [S,  2, 64]
```

使用 KV Cache 后，每次 Decode 不需要重新计算前面的 token。

当前 KV Cache 追加会重新分配并复制旧数据，数学结果正确，但长序列性能
还可以通过预分配或分块缓存进一步优化。

## 14. Greedy Generation

当前生成流程使用 Greedy Decoding：

```text
logits
   |
   v
argmax
   |
   v
next_token
   |
   v
使用 KV Cache 计算下一步
```

当前 C++ 核心尚未实现：

```text
temperature
top-p sampling
top-k sampling
repetition penalty
beam search
```

这些属于输出采样策略，不影响 Decoder 数学计算的正确性。

## 15. 基础算子清单

当前明文推理使用的基础操作如下：

| 类型 | 操作 |
|---|---|
| 权重加载 | BF16/F16/F32/F64 转 double |
| 数据访问 | Embedding Lookup |
| 线性代数 | Linear、矩阵向量乘法、点积 |
| 逐元素运算 | Add、Multiply、Bias Add |
| 归约 | Sum、Mean、Max |
| 归一化 | Square、Sqrt、Reciprocal |
| 激活 | Exp、SiLU、SwiGLU |
| Attention | QK、Scale、Softmax、Probability-V |
| 位置编码 | Sin、Cos、RoPE Rotation |
| 数据布局 | Reshape、Split Heads、Merge Heads |
| 缓存 | K/V Append、K/V Read |
| 输出 | Top-K、Argmax |

## 16. CPU 执行方式

当前实现：

```text
只使用 CPU
主要张量类型为 double
Linear 使用连续内存访问
Linear、Attention 和部分逐元素算子使用 OpenMP
不依赖 CUDA
不依赖 GPU
不链接 Poseidon 密文库
```

当前目标是保证算子边界清晰和结果可靠，尚未针对 CPU BLAS、NUMA、
量化或低精度推理做深度优化。

## 17. ExecutionTrace

`ExecutionTrace` 可以记录并导出以下中间节点：

```text
embedding
layer_N.input
layer_N.input_rmsnorm
layer_N.query_projection
layer_N.key_projection
layer_N.value_projection
layer_N.query_rope
layer_N.key_rope
layer_N.attention
layer_N.attention_output
layer_N.post_attention_residual
layer_N.post_attention_rmsnorm
layer_N.mlp_gate
layer_N.mlp_up
layer_N.mlp_swiglu
layer_N.mlp_output
layer_N.output
final_rmsnorm
last_token_logits
```

每个张量可以保存为原始 F64 文件，并在 `manifest.tsv` 中记录名称和形状。
这套节点将作为后续密文实现的逐算子误差参考。

## 18. Hugging Face 对照验证

运行：

```bash
python3 Trident/qwen/tools/validate_hf_checkpoint.py --threads 16
```

验证内容包括：

```text
Embedding
24 个 Decoder Layer 输出
Final RMSNorm
151936 维 Last-Token Logits
Top-5 Logits
8 步 Greedy Generation
Prefill
KV Cache Decode
```

当前官方 Qwen2.5-0.5B 对照结果：

```text
Embedding: 完全一致
Last-token logits 最大绝对误差: 约 1.32e-5
Top-5 token: 完全一致
8 步 Greedy token: 完全一致
整体结果: PASS
```

验证产物位于：

```text
Trident/qwen/validation_output
```

## 19. 明文算子到密文算子的映射

相对容易转换为同态计算的操作：

```text
Linear
Bias Add
Residual Add
明文常数乘法
```

需要重点设计 Packing 和 Ciphertext Rotation 的操作：

```text
矩阵乘法
按 hidden 维归约
Head 拆分与合并
RoPE
GQA 数据布局
KV Cache 布局
```

需要近似或协议配合的非线性操作：

```text
RMSNorm 的 inverse sqrt
SiLU 的 exp 和除法
Softmax 的 max、exp 和除法
Argmax/Top-K 的比较
```

Attention 中还包含：

```text
Encrypted Q x Encrypted K
Encrypted Probability x Encrypted V
```

这些是密文乘法深度、重线性化、Rescale 和 Bootstrap 规划的重点。

## 20. 建议的密文实现顺序

```text
1. 密文 Tensor 和 Packing 方案
2. Ciphertext-Plaintext Linear
3. Bias Add 和 Residual Add
4. RoPE 与 Slot Rotation
5. RMSNorm 多项式近似
6. Gate/Up/Down Linear
7. SiLU/SwiGLU 多项式近似
8. QK^T 与 GQA Attention 布局
9. Softmax 多项式近似
10. 单层 Encrypted Decoder
11. 多层误差和 Level Budget
12. 24 层完整推理
13. Encrypted KV Cache
14. Bootstrap 与长序列优化
```

每完成一个密文节点，都可以与 `ExecutionTrace` 导出的同名明文节点比较：

```text
最大绝对误差
平均绝对误差
RMSE
CKKS level
scale
noise budget
运行时间
```

这样可以在进入完整 24 层推理之前定位算子误差和参数问题。

## 21. 当前多 Token 密文 Softmax

明文参考仍使用第 9 节的标准稳定 Softmax。密文实现按可见 token 数量分三条路径：

```text
1 个 token: softmax 概率恒为 1，直接返回 V
2 个 token: p0 = sigmoid(s0 - s1)，O = V1 + p0 * (V0 - V1)
3 个及以上 token: 在线 logsumexp 递推
```

在线递推维护当前归一化常数 `L` 和加权输出 `O`：

```text
初始: L = s0, O = V0
delta = si - L
p = sigmoid(delta)
O = O + p * (Vi - O)
L = L + softplus(delta)
```

其中：

```text
sigmoid(x) = 1 / (1 + exp(-x))
softplus(x) = log(1 + exp(x))
```

这组递推在实数域与标准 Softmax 完全等价。CKKS 路径使用 Chebyshev 多项式分别近似
`sigmoid` 和 `softplus`，不解密 Q、K、V、分数、概率或 Attention 输出。

每个 `delta` 在多项式之前执行一次真实 Bootstrap，并恢复到 level 18；当前
degree-127 的 `sigmoid`/`softplus` 路径输出到 level 9。输出聚合每次密文乘法消耗
1 个 level，在 level 不足时按需 Bootstrap。前 3 个 Decoder 层边界仍只保留：

```text
post_attention_refresh
output_refresh
```

后层 residual 的数值范围明显增大，因此 Qwen2.5-0.5B 使用官方 checkpoint 校准得到的
逐层自举幅值缩放。缩放输入会额外消耗 1 个 level，所以从 layer 2 开始还要在
post-Attention RMSNorm 后执行 `mlp_input_refresh`，为 SiLU、SwiGLU 和 Down Projection
以及缩放后的 `output_refresh` 补足深度。该调度同时用于单 token、多 token 和
`target/tc128` 路径。

当前回归覆盖：

```text
2 token 特化公式
4 token 完整因果 Attention
3 token KV-cache prefill/decode
官方 checkpoint 的 3、4、8 token 真实 CKKS 单层
官方 checkpoint 的 4 token 真实 CKKS 多层
官方 checkpoint 的 4 token layer 23 + Final RMSNorm 真实 Bootstrap
```

启用 `--log-file` 后，每个在线 Softmax step 都输出 `delta_refresh`、`sigmoid`、
`softplus`、`aggregate_update` 以及按需 `aggregate_refresh` 的开始时刻、耗时、
密文数量和输入输出 level。

Final RMSNorm 使用 `[2.5, 55]` 上的 degree-31 inverse-square-root
Chebyshev 多项式。degree-31 会进入低深度 baby-step 求值路径；4-token、方差覆盖
`[6.2, 50]` 的密文回归中，CKKS 相对多项式参考的最大绝对误差约为 `5.6e-7`。

## 22. 多 Token 全模型真实密态运行

从 Poseidon 仓库根目录启动 4-token prefill、24 层 Qwen2.5-0.5B、真实 Bootstrap
和 1-token greedy 输出：

```bash
cd /home/guoshuai/github/poseidon

RUN_ID=$(date +%Y%m%d_%H%M%S)

nohup env OMP_NUM_THREADS=16 ./Trident/build/qwen/qwen_he_generate \
  --model Trident/qwen/pretrained_parameters/Qwen2.5-0.5B \
  --input-ids 9707,11,1246,525 \
  --max-new-tokens 1 \
  --max-layers 24 \
  --he-mode bootstrap \
  --bootstrap-layers 24 \
  --profile target \
  --tokens-per-cipher 4 \
  --log-file Trident/qwen/validation_output/qwen_he_generate_4token_target.log \
  > "Trident/qwen/validation_output/qwen_he_generate_4token_target_nohup_${RUN_ID}.log" \
  2>&1 < /dev/null &

echo $! | tee Trident/qwen/validation_output/qwen_he_generate_4token_target.pid
```

`target` 使用 `logN=16`、`log_slots=15` 和 tc128 参数检查。这里的
`--tokens-per-cipher 4` 只控制逻辑 token packing，不启用 compact/sparse Bootstrap；
每次刷新仍调用 Poseidon 的标准全槽 Bootstrap。

对于 `4/8/32/128` 等整数幅值缩放，自举前的除法仍使用一次高精度 rescale，
自举后的恢复乘法使用 Poseidon `multiply_const_direct`。恢复阶段不再额外消耗 level，
因此缩放后的边界自举稳定返回 level 19。target 的 layer 2 会先执行
`mlp_input_refresh`，避免 MLP 在 level 0 才进入 `output_refresh`。
